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
#include <string>
#include <thread>
#include <unordered_map>

#include <boost/endian/conversion.hpp>

#include <silkworm/common/cast.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/bitmap.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/stagedsync/listener_log_index.hpp>

#include "stagedsync.hpp"

namespace silkworm::stagedsync {

namespace fs = std::filesystem;

constexpr size_t kBitmapBufferSizeLimit = 512 * kMebi;

static void loader_function(etl::Entry entry, mdbx::cursor &target_table, MDBX_put_flags_t db_flags) {
    auto bm{roaring::Roaring::readSafe(byte_ptr_cast(entry.value.data()), entry.value.size())};
    Bytes last_chunk_index(entry.key.size() + 4, '\0');
    std::memcpy(&last_chunk_index[0], &entry.key[0], entry.key.size());
    boost::endian::store_big_u32(&last_chunk_index[entry.key.size()], UINT32_MAX);
    auto previous_bitmap_bytes{target_table.find(db::to_slice(last_chunk_index), false)};
    if (previous_bitmap_bytes) {
        bm |= roaring::Roaring::readSafe(previous_bitmap_bytes.value.char_ptr(), previous_bitmap_bytes.value.length());
        db_flags = MDBX_put_flags_t::MDBX_UPSERT;
    }
    while (bm.cardinality() > 0) {
        auto current_chunk{db::bitmap::cut_left(bm, db::bitmap::kBitmapChunkLimit)};
        // make chunk index
        Bytes chunk_index(entry.key.size() + 4, '\0');
        std::memcpy(&chunk_index[0], &entry.key[0], entry.key.size());
        uint64_t suffix{bm.cardinality() == 0 ? UINT32_MAX : current_chunk.maximum()};
        boost::endian::store_big_u32(&chunk_index[entry.key.size()], suffix);
        Bytes current_chunk_bytes(current_chunk.getSizeInBytes(), '\0');
        current_chunk.write(byte_ptr_cast(&current_chunk_bytes[0]));

        mdbx::slice k{db::to_slice(chunk_index)};
        mdbx::slice v{db::to_slice(current_chunk_bytes)};
        target_table.put(k, &v, db_flags);
    }
}

static void flush_bitmaps(etl::Collector &collector, std::unordered_map<std::string, roaring::Roaring> &map) {
    for (const auto &[key, bm] : map) {
        Bytes bitmap_bytes(bm.getSizeInBytes(), '\0');
        bm.write(byte_ptr_cast(bitmap_bytes.data()));
        etl::Entry entry{Bytes(byte_ptr_cast(key.c_str()), key.size()), bitmap_bytes};
        collector.collect(entry);
    }
    map.clear();
}

StageResult stage_log_index(TransactionManager &txn, const std::filesystem::path &etl_path) {
    fs::create_directories(etl_path);
    etl::Collector topic_collector(etl_path.string().c_str(), /* flush size */ 256 * kMebi);
    etl::Collector addresses_collector(etl_path.string().c_str(), /* flush size */ 256 * kMebi);

    // We take data from header table and transform it and put it in blockhashes table
    auto log_table{db::open_cursor(*txn, db::table::kLogs)};
    auto last_processed_block_number{db::stages::get_stage_progress(*txn, db::stages::kLogIndexKey)};

    // Extract
    SILKWORM_LOG(LogLevel::Info) << "Started Log Index Extraction" << std::endl;
    Bytes start(8, '\0');
    boost::endian::store_big_u64(&start[0], last_processed_block_number);

    uint64_t block_number{0};
    uint64_t topics_allocated_space{0};
    uint64_t addrs_allocated_space{0};
    std::unordered_map<std::string, roaring::Roaring> topic_bitmaps;
    std::unordered_map<std::string, roaring::Roaring> addresses_bitmaps;
    listener_log_index current_listener(block_number, &topic_bitmaps, &addresses_bitmaps, &topics_allocated_space,
                                        &addrs_allocated_space);

    if (log_table.seek(db::to_slice(start))) {
        auto log_data{log_table.current()};
        while (log_data) {
            block_number = boost::endian::load_big_u64(static_cast<uint8_t *>(log_data.key.iov_base));
            current_listener.set_block_number(block_number);
            cbor::input input(log_data.value.iov_base, log_data.value.iov_len);
            cbor::decoder decoder(input, current_listener);
            decoder.run();
            if (topics_allocated_space > kBitmapBufferSizeLimit) {
                flush_bitmaps(topic_collector, topic_bitmaps);
                SILKWORM_LOG(LogLevel::Info) << "Current Block: " << block_number << std::endl;
                topics_allocated_space = 0;
            }

            if (addrs_allocated_space > kBitmapBufferSizeLimit) {
                flush_bitmaps(addresses_collector, addresses_bitmaps);
                SILKWORM_LOG(LogLevel::Info) << "Current Block: " << block_number << std::endl;
                addrs_allocated_space = 0;
            }

            log_data = log_table.to_next(/*throw_notfound*/ false);
        }
    }

    log_table.close();

    flush_bitmaps(topic_collector, topic_bitmaps);
    flush_bitmaps(addresses_collector, addresses_bitmaps);

    SILKWORM_LOG(LogLevel::Info) << "Latest Block: " << block_number << std::endl;
    // Proceed only if we've done something
    SILKWORM_LOG(LogLevel::Info) << "Started Topics Loading" << std::endl;
    // if stage has never been touched then appending is safe
    MDBX_put_flags_t db_flags{last_processed_block_number ? MDBX_put_flags_t::MDBX_UPSERT
                                                          : MDBX_put_flags_t::MDBX_APPEND};

    // Eventually load collected items WITH transform (may throw)
    auto target{db::open_cursor(*txn, db::table::kLogTopicIndex)};

    topic_collector.load(target, loader_function, db_flags,
                         /* log_every_percent = */ 10);
    target.close();
    target = db::open_cursor(*txn, db::table::kLogAddressIndex);
    SILKWORM_LOG(LogLevel::Info) << "Started Address Loading" << std::endl;
    addresses_collector.load(target, loader_function, db_flags,
                             /* log_every_percent = */ 10);

    // Update progress height with last processed block
    db::stages::set_stage_progress(*txn, db::stages::kLogIndexKey, block_number);

    txn.commit();

    SILKWORM_LOG(LogLevel::Info) << "All Done" << std::endl;

    return StageResult::kSuccess;
}

StageResult unwind_log_index(TransactionManager &, const std::filesystem::path &, uint64_t) {
    throw std::runtime_error("Not Implemented.");
}

}  // namespace silkworm::stagedsync
