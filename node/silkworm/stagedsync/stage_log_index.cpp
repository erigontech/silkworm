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

#include <filesystem>
#include <string>
#include <unordered_map>

#include <silkworm/common/cast.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/bitmap.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/stagedsync/stage_logindex/listener_log_index.hpp>

#include "stagedsync.hpp"

namespace silkworm::stagedsync {

namespace fs = std::filesystem;

static constexpr size_t kBitmapBufferSizeLimit = 512_Mebi;

static void loader_function(const etl::Entry& entry, mdbx::cursor& target_table, MDBX_put_flags_t db_flags) {
    auto bm{roaring::Roaring::readSafe(byte_ptr_cast(entry.value.data()), entry.value.size())};
    Bytes last_chunk_index(entry.key.size() + 4, '\0');
    std::memcpy(&last_chunk_index[0], &entry.key[0], entry.key.size());
    endian::store_big_u32(&last_chunk_index[entry.key.size()], UINT32_MAX);
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
        endian::store_big_u32(&chunk_index[entry.key.size()], suffix);
        Bytes current_chunk_bytes(current_chunk.getSizeInBytes(), '\0');
        current_chunk.write(byte_ptr_cast(&current_chunk_bytes[0]));

        mdbx::slice k{db::to_slice(chunk_index)};
        mdbx::slice v{db::to_slice(current_chunk_bytes)};
        mdbx::error::success_or_throw(target_table.put(k, &v, db_flags));
    }
}

static void flush_bitmaps(etl::Collector& collector, std::unordered_map<std::string, roaring::Roaring>& map) {
    for (const auto& [key, bm] : map) {
        Bytes bitmap_bytes(bm.getSizeInBytes(), '\0');
        bm.write(byte_ptr_cast(bitmap_bytes.data()));
        collector.collect(etl::Entry{Bytes(byte_ptr_cast(key.c_str()), key.size()), bitmap_bytes});
    }
    map.clear();
}

StageResult stage_log_index(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t) {
    fs::create_directories(etl_path);
    etl::Collector topic_collector(etl_path, /* flush size */ 256_Mebi);
    etl::Collector addresses_collector(etl_path, /* flush size */ 256_Mebi);

    auto log_table{db::open_cursor(*txn, db::table::kLogs)};
    auto last_processed_block_number{db::stages::read_stage_progress(*txn, db::stages::kLogIndexKey)};

    // Extract
    log::Info() << "Started Log Index Extraction";
    Bytes start(8, '\0');
    endian::store_big_u64(&start[0], last_processed_block_number);

    uint64_t block_number{0};
    uint64_t topics_allocated_space{0};
    uint64_t addresses_allocated_space{0};
    // Two bitmaps to fill: topics and addresses
    std::unordered_map<std::string, roaring::Roaring> topic_bitmaps;
    std::unordered_map<std::string, roaring::Roaring> addresses_bitmaps;
    // CBOR decoder
    listener_log_index current_listener(block_number, &topic_bitmaps, &addresses_bitmaps, &topics_allocated_space,
                                        &addresses_allocated_space);

    auto log_data{log_table.lower_bound(db::to_slice(start), false)};
    while (log_data) {
        // Decode CBOR and distribute it to the 2 bitmaps
        block_number = endian::load_big_u64(static_cast<uint8_t*>(log_data.key.data()));
        current_listener.set_block_number(block_number);
        cbor::input input(log_data.value.data(), log_data.value.length());
        cbor::decoder decoder(input, current_listener);
        decoder.run();
        // Flushes
        if (topics_allocated_space > kBitmapBufferSizeLimit) {
            flush_bitmaps(topic_collector, topic_bitmaps);
            log::Info() << "Current Block: " << block_number;
            topics_allocated_space = 0;
        }

        if (addresses_allocated_space > kBitmapBufferSizeLimit) {
            flush_bitmaps(addresses_collector, addresses_bitmaps);
            log::Info() << "Current Block: " << block_number;
            addresses_allocated_space = 0;
        }

        log_data = log_table.to_next(/*throw_notfound*/ false);
    }

    log_table.close();
    // Flush once it is done
    flush_bitmaps(topic_collector, topic_bitmaps);
    flush_bitmaps(addresses_collector, addresses_bitmaps);

    log::Info() << "Latest Block: " << block_number;
    // Proceed only if we've done something
    log::Info() << "Started Topics Loading";
    // if stage has never been touched then appending is safe
    MDBX_put_flags_t db_flags{last_processed_block_number ? MDBX_put_flags_t::MDBX_UPSERT
                                                          : MDBX_put_flags_t::MDBX_APPEND};

    // Eventually load collected items WITH transform (may throw)
    auto target{db::open_cursor(*txn, db::table::kLogTopicIndex)};
    topic_collector.load(target, loader_function, db_flags);
    target.close();
    target = db::open_cursor(*txn, db::table::kLogAddressIndex);
    log::Info() << "Started Address Loading";
    addresses_collector.load(target, loader_function, db_flags);

    // Update progress height with last processed block
    db::stages::write_stage_progress(*txn, db::stages::kLogIndexKey, block_number);

    txn.commit();

    log::Info() << "All Done";

    return StageResult::kSuccess;
}

static StageResult unwind_log_index(db::RWTxn& txn, etl::Collector& collector, uint64_t unwind_to, bool topics) {
    auto index_table{topics ? db::open_cursor(*txn, db::table::kLogTopicIndex)
                            : db::open_cursor(*txn, db::table::kLogAddressIndex)};
    if (unwind_to >= db::stages::read_stage_progress(*txn, db::stages::kLogIndexKey)) {
        return StageResult::kSuccess;
    }

    // Latest bitmap
    auto data{index_table.to_first(/*throw_notfound=*/false)};
    while (data) {
        // Get bitmap data of current element
        auto key{db::from_slice(data.key)};
        auto bitmap_data{db::from_slice(data.value)};

        auto bm{roaring::Roaring::readSafe(byte_ptr_cast(bitmap_data.data()), bitmap_data.size())};
        // Check for keys that can be skipped
        if (bm.maximum() <= unwind_to) {
            data = index_table.to_next(/*throw_notfound*/ false);
            continue;
        }
        // adjust bitmaps
        if (bm.minimum() <= unwind_to) {
            // Erase elements that are > unwind_to
            bm &= roaring::Roaring(roaring::api::roaring_bitmap_from_range(0, unwind_to + 1, 1));
            auto new_bitmap{Bytes(bm.getSizeInBytes(), '\0')};
            bm.write(byte_ptr_cast(&new_bitmap[0]));
            // make new key
            Bytes new_key(key.size(), '\0');
            std::memcpy(&new_key[0], key.data(), key.size());
            endian::store_big_u32(&new_key[new_key.size() - 4], UINT32_MAX);
            // collect higher bitmap
            collector.collect(etl::Entry{new_key, new_bitmap});
        }
        // erase index
        index_table.erase(true);
        data = index_table.to_next(/*throw_notfound*/ false);
    }

    collector.load(index_table, nullptr, MDBX_put_flags_t::MDBX_UPSERT);
    txn.commit();

    return StageResult::kSuccess;
}

StageResult unwind_log_index(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to) {
    etl::Collector collector(etl_path, /* flush size */ 256_Mebi);

    log::Info() << "Started Topic Index Unwind";
    auto result{unwind_log_index(txn, collector, unwind_to, true)};
    collector.clear();
    if (result != StageResult::kSuccess) {
        return result;
    }
    log::Info() << "Started Address Index Unwind";
    result = unwind_log_index(txn, collector, unwind_to, false);
    collector.clear();
    if (result != StageResult::kSuccess) {
        return result;
    }
    db::stages::write_stage_progress(*txn, db::stages::kLogIndexKey, unwind_to);
    log::Info() << "All Done";
    return StageResult::kSuccess;
}

void prune_log_index(db::RWTxn& txn, etl::Collector& collector, uint64_t prune_from, bool topics) {
    auto last_processed_block{db::stages::read_stage_progress(*txn, db::stages::kLogIndexKey)};

    auto index_table{topics ? db::open_cursor(*txn, db::table::kLogTopicIndex)
                            : db::open_cursor(*txn, db::table::kLogAddressIndex)};

    if (index_table.to_first(/* throw_notfound = */ false)) {
        auto data{index_table.current()};
        while (data) {
            // Get bitmap data of current element
            auto key{db::from_slice(data.key)};
            auto bitmap_data{db::from_slice(data.value)};
            auto bm{roaring::Roaring::readSafe(byte_ptr_cast(bitmap_data.data()), bitmap_data.size())};
            // Check whether we should skip the current bitmap
            if (bm.minimum() >= prune_from) {
                data = index_table.to_next(/*throw_notfound*/ false);
                continue;
            }
            // check if prune can be applied
            if (bm.maximum() >= prune_from) {
                // Erase elements that are below prune_from
                bm &=
                    roaring::Roaring(roaring::api::roaring_bitmap_from_range(prune_from, last_processed_block + 1, 1));
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
}

StageResult prune_log_index(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from) {
    etl::Collector collector(etl_path, /* flush size */ 256_Mebi);

    log::Info() << "Pruning Log Index from: " << prune_from;
    prune_log_index(txn, collector, prune_from, true);
    collector.clear();
    prune_log_index(txn, collector, prune_from, false);
    collector.clear();

    log::Info() << "Pruning Log Index finished...";
    return StageResult::kSuccess;
}

}  // namespace silkworm::stagedsync
