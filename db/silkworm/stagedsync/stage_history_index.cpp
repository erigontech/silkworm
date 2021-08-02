/*
   Copyright 2021 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>

#include <boost/endian/conversion.hpp>

#include <silkworm/common/cast.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/bitmap.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>

#include "stagedsync.hpp"

namespace silkworm::stagedsync {

constexpr size_t kBitmapBufferSizeLimit = 256 * kMebi;

namespace fs = std::filesystem;

static StageResult history_index_stage(TransactionManager &txn, const std::filesystem::path &etl_path, bool storage) {
    fs::create_directories(etl_path);
    etl::Collector collector(etl_path.string().c_str(), /* flush size */ 512 * kMebi);

    // We take data from header table and transform it and put it in blockhashes table
    db::MapConfig changeset_config = storage ? db::table::kPlainStorageChangeSet : db::table::kPlainAccountChangeSet;
    db::MapConfig index_config = storage ? db::table::kStorageHistory : db::table::kAccountHistory;
    const char *stage_key = storage ? db::stages::kStorageHistoryIndexKey : db::stages::kAccountHistoryKey;

    auto changeset_table{db::open_cursor(*txn, changeset_config)};
    std::unordered_map<std::string, roaring::Roaring64Map> bitmaps;

    auto last_processed_block_number{db::stages::get_stage_progress(*txn, stage_key)};

    // Extract
    SILKWORM_LOG(LogLevel::Info) << "Started " << (storage ? "Storage" : "Account") << " Index Extraction" << std::endl;
    Bytes start{db::block_key(last_processed_block_number + 1)};

    size_t allocated_space{0};
    uint64_t block_number{0};

    if (changeset_table.seek(db::to_slice(start))) {
        auto data{changeset_table.current()};
        while (data) {
            std::string composite_key;
            if (storage) {
                char composite_key_array[kHashLength + kAddressLength];
                auto data_key_view{db::from_slice(data.key).substr(8)};
                std::memcpy(&composite_key_array[0], data_key_view.data(), kAddressLength);
                std::memcpy(&composite_key_array[kAddressLength], data.value.iov_base, kHashLength);
                composite_key = std::string(composite_key_array);
            } else {
                composite_key = std::string(data.value.char_ptr(), kAddressLength);
            }

            if (bitmaps.find(composite_key) == bitmaps.end()) {
                bitmaps.emplace(composite_key, roaring::Roaring64Map());
            }
            block_number = boost::endian::load_big_u64(static_cast<uint8_t *>(data.key.iov_base));
            bitmaps.at(composite_key).add(block_number);
            allocated_space += 8;
            if (64 * bitmaps.size() + allocated_space > kBitmapBufferSizeLimit) {
                for (const auto &[key, bm] : bitmaps) {
                    Bytes bitmap_bytes(bm.getSizeInBytes(), '\0');
                    bm.write(byte_ptr_cast(bitmap_bytes.data()));
                    etl::Entry entry{Bytes(byte_ptr_cast(key.c_str()), key.size()), bitmap_bytes};
                    collector.collect(entry);
                }
                SILKWORM_LOG(LogLevel::Info) << "Current Block: " << block_number << std::endl;
                bitmaps.clear();
                allocated_space = 0;
            }
            data = changeset_table.to_next(/*throw_notfound*/ false);
        }
    }
    changeset_table.close();

    for (const auto &[key, bm] : bitmaps) {
        Bytes bitmap_bytes(bm.getSizeInBytes(), '\0');
        bm.write(byte_ptr_cast(bitmap_bytes.data()));
        etl::Entry entry{Bytes(byte_ptr_cast(key.c_str()), key.size()), bitmap_bytes};
        collector.collect(entry);
    }
    bitmaps.clear();

    SILKWORM_LOG(LogLevel::Info) << "Latest Block: " << block_number << std::endl;

    // Proceed only if we've done something
    if (collector.size()) {
        SILKWORM_LOG(LogLevel::Info) << "Started Loading" << std::endl;

        MDBX_put_flags_t db_flags{last_processed_block_number ? MDBX_put_flags_t::MDBX_UPSERT
                                                              : MDBX_put_flags_t::MDBX_APPEND};

        // Eventually load collected items WITH transform (may throw)
        auto target{db::open_cursor(*txn, index_config)};
        collector.load(
            target,
            [](etl::Entry entry, mdbx::cursor &history_index_table, MDBX_put_flags_t db_flags) {
                auto bm{roaring::Roaring64Map::readSafe(byte_ptr_cast(entry.value.data()), entry.value.size())};

                Bytes last_chunk_index(entry.key.size() + 8, '\0');
                std::memcpy(&last_chunk_index[0], &entry.key[0], entry.key.size());
                boost::endian::store_big_u64(&last_chunk_index[entry.key.size()], UINT64_MAX);
                auto previous_bitmap_bytes{history_index_table.find(db::to_slice(last_chunk_index), false)};
                if (previous_bitmap_bytes) {
                    bm |= roaring::Roaring64Map::readSafe(previous_bitmap_bytes.value.char_ptr(),
                                                          previous_bitmap_bytes.value.length());
                    db_flags = MDBX_put_flags_t::MDBX_UPSERT;
                }
                while (bm.cardinality() > 0) {
                    auto current_chunk{db::bitmap::cut_left(bm, db::bitmap::kBitmapChunkLimit)};
                    // make chunk index
                    Bytes chunk_index(entry.key.size() + 8, '\0');
                    std::memcpy(&chunk_index[0], &entry.key[0], entry.key.size());
                    uint64_t suffix{bm.cardinality() == 0 ? UINT64_MAX : current_chunk.maximum()};
                    boost::endian::store_big_u64(&chunk_index[entry.key.size()], suffix);
                    Bytes current_chunk_bytes(current_chunk.getSizeInBytes(), '\0');
                    current_chunk.write(byte_ptr_cast(&current_chunk_bytes[0]));
                    mdbx::slice k{db::to_slice(chunk_index)};
                    mdbx::slice v{db::to_slice(current_chunk_bytes)};
                    history_index_table.put(k, &v, db_flags);
                }
            },
            db_flags, /* log_every_percent = */ 20);

        // Update progress height with last processed block
        db::stages::set_stage_progress(*txn, stage_key, block_number);
        txn.commit();

    } else {
        SILKWORM_LOG(LogLevel::Info) << "Nothing to process" << std::endl;
    }

    SILKWORM_LOG(LogLevel::Info) << "All Done" << std::endl;

    return StageResult::kSuccess;
}

StageResult stage_account_history(TransactionManager &txn, const std::filesystem::path &etl_path) {
    return history_index_stage(txn, etl_path, false);
}
StageResult stage_storage_history(TransactionManager &txn, const std::filesystem::path &etl_path) {
    return history_index_stage(txn, etl_path, true);
}

StageResult unwind_account_history(TransactionManager &, const std::filesystem::path &, uint64_t) {
    throw std::runtime_error("Not Implemented.");
}

StageResult unwind_storage_history(TransactionManager &, const std::filesystem::path &, uint64_t) {
    throw std::runtime_error("Not Implemented.");
}

}  // namespace silkworm::stagedsync
