/*
   Copyright 2021-2022 The Silkworm Authors

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

#include <unordered_map>

#include <silkworm/common/cast.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/bitmap.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/etl/collector.hpp>

#include "stagedsync.hpp"

namespace silkworm::stagedsync {

static constexpr size_t kBitmapBufferSizeLimit = 256_Mebi;

namespace fs = std::filesystem;

static StageResult history_index_stage(db::RWTxn& txn, const std::filesystem::path& etl_path, bool storage) {
    fs::create_directories(etl_path);

    etl::Collector collector(etl_path, /* flush size */ 512_Mebi);
    std::unordered_map<std::string, roaring::Roaring64Map> bitmaps;

    auto flush_bitmaps_to_etl = [&collector, &bitmaps] {
        for (const auto& [bitmap_key, bitmap] : bitmaps) {
            Bytes bitmap_bytes(bitmap.getSizeInBytes(), '\0');
            bitmap.write(byte_ptr_cast(bitmap_bytes.data()));
            collector.collect(etl::Entry{Bytes(byte_ptr_cast(bitmap_key.c_str()), bitmap_key.size()), bitmap_bytes});
        }
        bitmaps.clear();
    };

    // We take data from changesets and turn it to indexes, so from [Block Number => Location] to [Location => Block
    // Number]
    db::MapConfig changeset_config = storage ? db::table::kStorageChangeSet : db::table::kAccountChangeSet;
    db::MapConfig index_config = storage ? db::table::kStorageHistory : db::table::kAccountHistory;
    const char* stage_key = storage ? db::stages::kStorageHistoryIndexKey : db::stages::kAccountHistoryIndexKey;

    auto changeset_table{db::open_cursor(*txn, changeset_config)};
    auto last_processed_block_number{db::stages::read_stage_progress(*txn, stage_key)};
    Bytes start{db::block_key(last_processed_block_number + 1)};

    // Extract
    log::Info() << "Started " << (storage ? "Storage" : "Account")
                << " Index Extraction. From: " << (last_processed_block_number + 1);

    size_t allocated_space{0};
    BlockNum block_number{0};
    auto data{changeset_table.lower_bound(db::to_slice(start))};
    while (data) {
        std::string composite_key;
        auto key{db::from_slice(data.key)};
        auto value{db::from_slice(data.value)};
        auto [db_key, _]{db::changeset_to_plainstate_format(key, value)};
        // Make the composite key accordingly whether we are dealing with storages or accounts
        if (storage) {
            // Storage: Address + Location
            composite_key.resize(kAddressLength + kHashLength);
            std::memcpy(&composite_key[0], &db_key[0], kAddressLength);
            std::memcpy(&composite_key[kAddressLength], &db_key[kAddressLength + db::kIncarnationLength], kHashLength);
        } else {
            // Account: Address
            composite_key = std::string(data.value.char_ptr(), kAddressLength);
        }
        // Initialize composite key if needed
        if (bitmaps.find(composite_key) == bitmaps.end()) {
            bitmaps.emplace(composite_key, roaring::Roaring64Map());
        }
        // Add block number to the bitmap of current key
        block_number = endian::load_big_u64(static_cast<uint8_t*>(data.key.data()));
        bitmaps.at(composite_key).add(block_number);
        allocated_space += 8;
        // Flush to ETL
        if (64 * bitmaps.size() + allocated_space > kBitmapBufferSizeLimit) {
            flush_bitmaps_to_etl();
            allocated_space = 0;
            log::Info() << "Current Block: " << block_number;
        }
        data = changeset_table.to_next(/*throw_notfound*/ false);
    }
    changeset_table.close();
    if (allocated_space != 0) {
        flush_bitmaps_to_etl();
    }

    log::Info() << "Latest Block: " << block_number;

    // Proceed only if we've done something
    if (!collector.empty()) {
        log::Info() << "Started Loading";

        MDBX_put_flags_t db_flags{last_processed_block_number ? MDBX_put_flags_t::MDBX_UPSERT
                                                              : MDBX_put_flags_t::MDBX_APPEND};

        // Eventually load collected items WITH transform (may throw)
        auto target{db::open_cursor(*txn, index_config)};
        collector.load(
            target,
            [](const etl::Entry& entry, mdbx::cursor& history_index_table, MDBX_put_flags_t put_flags) {
                auto bm{roaring::Roaring64Map::readSafe(byte_ptr_cast(entry.value.data()), entry.value.size())};
                // Check whether we still need to rework the previous entry
                Bytes last_chunk_index(entry.key.size() + 8, '\0');
                std::memcpy(&last_chunk_index[0], &entry.key[0], entry.key.size());
                endian::store_big_u64(&last_chunk_index[entry.key.size()], UINT64_MAX);
                auto previous_bitmap_bytes{history_index_table.find(db::to_slice(last_chunk_index), false)};
                // If we have an unfinished bitmap for the current location then continue working on it
                if (previous_bitmap_bytes) {
                    // Merge previous and current bitmap
                    bm |= roaring::Roaring64Map::readSafe(previous_bitmap_bytes.value.char_ptr(),
                                                          previous_bitmap_bytes.value.length());
                    put_flags = MDBX_put_flags_t::MDBX_UPSERT;
                }
                while (bm.cardinality() > 0) {
                    // Divide in different bitmaps of different (chunks) and push all of them individually
                    auto current_chunk{db::bitmap::cut_left(bm, db::bitmap::kBitmapChunkLimit)};
                    // Make chunk index (Location + Suffix )
                    Bytes chunk_index(entry.key.size() + 8, '\0');
                    std::memcpy(&chunk_index[0], &entry.key[0], entry.key.size());
                    // Suffix is either the maximum Block Number of the bitmap or if it's the last chunk: UINT64_MAX
                    BlockNum suffix{bm.cardinality() == 0 ? UINT64_MAX : current_chunk.maximum()};
                    endian::store_big_u64(&chunk_index[entry.key.size()], suffix);
                    // Push chunk to database
                    Bytes current_chunk_bytes(current_chunk.getSizeInBytes(), '\0');
                    current_chunk.write(byte_ptr_cast(&current_chunk_bytes[0]));
                    mdbx::slice k{db::to_slice(chunk_index)};
                    mdbx::slice v{db::to_slice(current_chunk_bytes)};
                    mdbx::error::success_or_throw(history_index_table.put(k, &v, put_flags));
                }
            },
            db_flags);

        // Update progress height with last processed block
        db::stages::write_stage_progress(*txn, stage_key, block_number);
        txn.commit();

    } else {
        log::Info() << "Nothing to process";
    }

    log::Info() << "All Done";

    return StageResult::kSuccess;
}

StageResult history_index_unwind(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to,
                                 bool storage) {
    // We take data from header table and transform it and put it in blockhashes table
    db::MapConfig index_config = storage ? db::table::kStorageHistory : db::table::kAccountHistory;
    const char* stage_key = storage ? db::stages::kStorageHistoryIndexKey : db::stages::kAccountHistoryIndexKey;
    etl::Collector collector(etl_path,
                             /* flush size */ 10_Mebi);  // We do not unwind by many blocks usually

    auto index_table{db::open_cursor(*txn, index_config)};
    // Extract
    log::Info() << "Started " << (storage ? "Storage" : "Account") << " Index Unwind";
    if (index_table.to_first(/* throw_notfound = */ false)) {
        auto data{index_table.current()};
        while (data) {
            // Get bitmap data of current element
            auto key{db::from_slice(data.key)};
            auto bitmap_data{db::from_slice(data.value)};
            auto bm{roaring::Roaring64Map::readSafe(byte_ptr_cast(bitmap_data.data()), bitmap_data.size())};
            // Check whether we should skip the current bitmap
            if (bm.maximum() <= unwind_to) {
                data = index_table.to_next(/*throw_notfound*/ false);
                continue;
            }
            // check if unwind can be applied
            if (bm.minimum() <= unwind_to) {
                // Erase elements that are > unwind_to
                bm &= roaring::Roaring64Map(roaring::api::roaring_bitmap_from_range(0, unwind_to + 1, 1));
                Bytes new_bitmap(bm.getSizeInBytes(), '\0');
                bm.write(byte_ptr_cast(&new_bitmap[0]));
                // generates new key
                Bytes new_key(key.size(), '\0');
                std::memcpy(&new_key[0], key.data(), key.size());
                endian::store_big_u32(&new_key[new_key.size() - 4], UINT32_MAX);
                // replace with new index
                collector.collect(etl::Entry{new_key, new_bitmap});
            }
            index_table.erase(/* whole_multivalue = */ true);
            data = index_table.to_next(/*throw_notfound*/ false);
        }
    }

    db::stages::write_stage_progress(*txn, stage_key, unwind_to);
    collector.load(index_table, nullptr, MDBX_put_flags_t::MDBX_UPSERT);
    txn.commit();
    log::Info() << "All Done";

    return StageResult::kSuccess;
}

StageResult history_index_prune(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from,
                                bool storage) {
    db::MapConfig index_config = storage ? db::table::kStorageHistory : db::table::kAccountHistory;
    const char* stage_key = storage ? db::stages::kStorageHistoryIndexKey : db::stages::kAccountHistoryIndexKey;
    etl::Collector collector(etl_path.string().c_str(),
                             /* flush size */ 10 * kMebi);  // We do not prune many blocks usually

    auto last_processed_block{db::stages::read_stage_progress(*txn, stage_key)};

    auto index_table{db::open_cursor(*txn, index_config)};
    log::Info() << "Pruning " << (storage ? "Storage" : "Account") << " History from: " << prune_from;

    if (index_table.to_first(/* throw_notfound = */ false)) {
        auto data{index_table.current()};
        while (data) {
            // Get bitmap data of current element
            auto key{db::from_slice(data.key)};
            auto bitmap_data{db::from_slice(data.value)};
            auto bm{roaring::Roaring64Map::readSafe(byte_ptr_cast(bitmap_data.data()), bitmap_data.size())};
            // Check whether we should skip the current bitmap
            if (bm.minimum() >= prune_from) {
                data = index_table.to_next(/*throw_notfound*/ false);
                continue;
            }
            // check if prune can be applied
            if (bm.maximum() >= prune_from) {
                // Erase elements that are below prune_from
                bm &= roaring::Roaring64Map(
                    roaring::api::roaring_bitmap_from_range(prune_from, last_processed_block + 1, 1));
                Bytes new_bitmap(bm.getSizeInBytes(), '\0');
                bm.write(byte_ptr_cast(&new_bitmap[0]));
                // replace with new index
                etl::Entry entry{Bytes{key}, new_bitmap};
                collector.collect(entry);
            }
            index_table.erase(/* whole_multivalue = */ true);
            data = index_table.to_next(/*throw_notfound*/ false);
        }
    }

    collector.load(index_table, nullptr, MDBX_put_flags_t::MDBX_UPSERT);
    txn.commit();
    log::Info() << "Pruning " << (storage ? "Storage" : "Account") << " History finished...";

    return StageResult::kSuccess;
}

StageResult stage_account_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t) {
    return history_index_stage(txn, etl_path, false);
}
StageResult stage_storage_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t) {
    return history_index_stage(txn, etl_path, true);
}

StageResult unwind_account_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to) {
    return history_index_unwind(txn, etl_path, unwind_to, false);
}

StageResult unwind_storage_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to) {
    return history_index_unwind(txn, etl_path, unwind_to, true);
}

StageResult prune_account_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from) {
    return history_index_prune(txn, etl_path, prune_from, false);
}
StageResult prune_storage_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from) {
    return history_index_prune(txn, etl_path, prune_from, true);
}

}  // namespace silkworm::stagedsync
