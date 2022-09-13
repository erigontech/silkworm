/*
   Copyright 2022 The Silkworm Authors

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

#include "bitmap.hpp"

#include <silkworm/common/binary_search.hpp>
#include <silkworm/common/cast.hpp>
#include <silkworm/concurrency/signal_handler.hpp>

namespace silkworm::db::bitmap {

void IndexLoader::merge_bitmaps(RWTxn& txn, size_t key_size, etl::Collector* bitmaps_collector) {
    const Bytes last_shard_suffix{db::block_key(UINT64_MAX)};
    const size_t optimal_shard_size{
        db::max_value_size_for_leaf_page(*txn, key_size + /*shard upper_bound*/ sizeof(uint64_t))};

    db::Cursor target(txn, index_config_);
    etl::LoadFunc load_func{[&last_shard_suffix, &optimal_shard_size](const etl::Entry& entry,
                                                                      mdbx::cursor& index_cursor,
                                                                      MDBX_put_flags_t put_flags) -> void {
        auto new_bitmap{db::bitmap::parse(entry.value)};  // Bitmap being merged

        // Check whether we have any previous shard to merge with
        Bytes shard_key{
            entry.key
                .substr(0, entry.key.size() - sizeof(uint16_t)) /* remove etl ordering suffix */
                .append(last_shard_suffix)};                    /* and append const suffix for last key */

        if (auto index_data{index_cursor.find(db::to_slice(shard_key), /*throw_notfound=*/false)}; index_data.done) {
            // Merge previous and current bitmap
            new_bitmap |= db::bitmap::parse(index_data.value);
            index_cursor.erase();  // Delete currently found record as it'll be rewritten
        }

        // Consume bitmap splitting in shards
        while (!new_bitmap.isEmpty()) {
            auto shard{db::bitmap::cut_left(new_bitmap, optimal_shard_size)};
            const BlockNum suffix{new_bitmap.isEmpty() /* consumed to last chunk */ ? UINT64_MAX
                                                                                    : shard.maximum()};
            endian::store_big_u64(&shard_key[shard_key.size() - sizeof(BlockNum)], suffix);
            Bytes shard_bytes{db::bitmap::to_bytes(shard)};
            mdbx::slice k{db::to_slice(shard_key)};
            mdbx::slice v{db::to_slice(shard_bytes)};
            mdbx::error::success_or_throw(index_cursor.put(k, &v, put_flags));
        }
    }};

    bitmaps_collector->load(target,
                            load_func,
                            target.empty() ? MDBX_put_flags_t::MDBX_APPEND : MDBX_put_flags_t::MDBX_UPSERT);
    bitmaps_collector->clear();
}

void IndexLoader::unwind_bitmaps(RWTxn& txn, BlockNum to, const std::map<Bytes, bool>& keys) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    db::Cursor target(txn, index_config_);
    for (const auto& [key, created] : keys) {
        // Log and abort check
        if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            if (SignalHandler::signalled()) {
                throw std::runtime_error("Operation cancelled");
            }

            std::unique_lock log_lck(log_mtx_);
            current_key_ = abridge(to_hex(key, true), kAddressLength);
            log_time = now + 5s;
        }

        if (created) {
            // Key was created in the batch we're unwinding
            // Delete all its history
            db::cursor_erase_prefix(target, key);
            continue;
        }

        // Locate previous incomplete shard. There's always one if account has been touched at least once in
        // changeset !
        const Bytes shard_key{key + db::block_key(UINT64_MAX)};
        auto index_data{target.find(db::to_slice(shard_key), false)};
        while (index_data) {
            const auto index_data_key_view{db::from_slice(index_data.key)};
            if (!index_data_key_view.starts_with(key)) {
                break;
            }

            auto db_bitmap{db::bitmap::parse(index_data.value)};
            if (db_bitmap.maximum() <= to) {
                break;
            }

            while (!db_bitmap.isEmpty() && db_bitmap.maximum() > to) {
                db_bitmap.remove(db_bitmap.maximum());
            }

            if (db_bitmap.isEmpty()) {
                // Delete this record and move to previous shard (if any)
                target.erase();
                index_data = target.to_previous(false);
                continue;
            }

            // Replace current record with the new bitmap ensuring is marked as last shard
            target.erase();
            Bytes shard_bytes{db::bitmap::to_bytes(db_bitmap)};
            target.insert(db::to_slice(shard_key), db::to_slice(shard_bytes));
            break;
        }
    }

    std::unique_lock log_lck(log_mtx_);
    current_key_.clear();
}

void IndexLoader::prune_bitmaps(RWTxn& txn, BlockNum threshold) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    db::Cursor target(txn, index_config_);
    auto target_data{target.to_first(/*throw_notfound=*/false)};
    while (target_data) {
        const auto data_key_view{db::from_slice(target_data.key)};
        // Log and abort check
        if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            if (SignalHandler::signalled()) {
                throw std::runtime_error("Operation cancelled");
            }
            std::unique_lock log_lck(log_mtx_);
            current_key_ = abridge(to_hex(data_key_view, true), kAddressLength);
            log_time = now + 5s;
        }

        // Suffix indicates the upper bound of the shard.
        const auto suffix{endian::load_big_u64(&data_key_view[data_key_view.size() - sizeof(BlockNum)])};

        // If below pruning threshold simply delete the record
        if (suffix <= threshold) {
            target.erase();
        } else {
            // Read current bitmap
            auto bitmap{db::bitmap::parse(target_data.value)};
            bool shard_shrunk{false};
            while (!bitmap.isEmpty() && bitmap.minimum() <= threshold) {
                bitmap.remove(bitmap.minimum());
                shard_shrunk = true;
            }
            if (bitmap.isEmpty() || shard_shrunk) {
                if (!bitmap.isEmpty()) {
                    Bytes new_shard_data{db::bitmap::to_bytes(bitmap)};
                    target.update(db::to_slice(data_key_view), db::to_slice(new_shard_data));
                } else {
                    target.erase();
                }
            }
        }

        target_data = target.to_next(/*throw_notfound=*/false);
    }

    std::unique_lock log_lck(log_mtx_);
    current_key_.clear();
}

void IndexLoader::flush_bitmaps_to_etl(absl::btree_map<Bytes, roaring::Roaring64Map>& bitmaps,
                                       etl::Collector* collector, uint16_t flush_count) {
    for (auto& [key, bitmap] : bitmaps) {
        Bytes etl_key(key.size() + sizeof(uint16_t), '\0');
        std::memcpy(&etl_key[0], key.data(), key.size());
        endian::store_big_u16(&etl_key[key.size()], flush_count);
        collector->collect({etl_key, db::bitmap::to_bytes(bitmap)});
    }
    bitmaps.clear();
}

std::optional<uint64_t> seek(const roaring::Roaring64Map& bitmap, uint64_t n) {
    auto it{bitmap.begin()};
    if (it.move(n)) {
        return *it;
    }
    return std::nullopt;
}

static void remove_range_impl(roaring::Roaring& bm, uint64_t min, uint64_t max) {
    roaring::api::roaring_bitmap_remove_range(&bm.roaring, min, max);
}

static void remove_range_impl(roaring::Roaring64Map& bm, uint64_t min, uint64_t max) {
    for (uint64_t k = min; k < max; ++k) {
        bm.remove(k);
    }
}

template <typename RoaringMap>
RoaringMap cut_left_impl(RoaringMap& bm, uint64_t size_limit) {
    if (bm.getSizeInBytes() <= size_limit) {
        RoaringMap res = bm;
        res.runOptimize();
        bm = RoaringMap();
        return res;
    }

    const auto from{bm.minimum()};
    const auto min_max{bm.maximum() - bm.minimum()};

    const auto cutting_point{binary_find_if(min_max, [&](size_t i) {
        RoaringMap current_bitmap(roaring::api::roaring_bitmap_from_range(from, from + i + 1, 1));
        current_bitmap &= bm;
        current_bitmap.runOptimize();
        return current_bitmap.getSizeInBytes() > size_limit;
    })};

    // no +1 because binary_find_if returns the element which is just above the threshold - but we need <=
    RoaringMap res(roaring::api::roaring_bitmap_from_range(from, from + cutting_point, 1));
    res &= bm;
    res.runOptimize();
    remove_range_impl(bm, from, from + cutting_point);
    return res;
}

roaring::Roaring cut_left(roaring::Roaring& bm, uint64_t size_limit) { return cut_left_impl(bm, size_limit); }

roaring::Roaring64Map cut_left(roaring::Roaring64Map& bm, uint64_t size_limit) { return cut_left_impl(bm, size_limit); }

Bytes to_bytes(roaring::Roaring64Map& bitmap) {
    if (!bitmap.isEmpty()) {
        Bytes ret(bitmap.getSizeInBytes(), '\0');
        bitmap.write(byte_ptr_cast(&ret[0]));
        return ret;
    }
    return {};
}

roaring::Roaring64Map parse(const mdbx::slice& data) {
    return roaring::Roaring64Map::readSafe(data.char_ptr(), data.length());
}

roaring::Roaring64Map parse(const ByteView data) {
    return roaring::Roaring64Map::readSafe(byte_ptr_cast(&data[0]), data.size());
}
}  // namespace silkworm::db::bitmap
