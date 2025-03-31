// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "bitmap.hpp"

#include <stdexcept>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/infra/common/binary_search.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>

#include "etl_mdbx_collector.hpp"

namespace silkworm::datastore::kvdb::bitmap {

template <typename BlockUpperBound>
Bytes upper_bound_suffix(BlockUpperBound value) {
    // Cannot use block_key because we need block number serialized in sizeof(BlockUpperBound) bytes
    Bytes shard_suffix(sizeof(BlockUpperBound), '\0');
    intx::be::unsafe::store<BlockUpperBound>(&shard_suffix[0], value);
    return shard_suffix;
}

template <typename RoaringMap>
RoaringMap parse_impl(const mdbx::slice& data) {
    return RoaringMap::readSafe(data.char_ptr(), data.length());
}

template <typename RoaringMap>
RoaringMap parse_impl(const ByteView data) {
    return RoaringMap::readSafe(byte_ptr_cast(&data[0]), data.size());
}

template <typename RoaringMap>
void remove_range_impl(RoaringMap& bm, uint64_t min, uint64_t max);

template <>
[[maybe_unused]] void remove_range_impl<roaring::Roaring>(roaring::Roaring& bm, uint64_t min, uint64_t max) {
    roaring::api::roaring_bitmap_remove_range(&bm.roaring, min, max);
}

template <>
[[maybe_unused]] void remove_range_impl(roaring::Roaring64Map& bm, uint64_t min, uint64_t max) {
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
    remove_range_impl<RoaringMap>(bm, from, from + cutting_point);
    return res;
}

template <typename RoaringMap, typename BlockUpperBound>
void IndexLoader::merge_bitmaps_impl(RWTxn& txn, size_t key_size, datastore::kvdb::Collector* bitmaps_collector) {
    // Cannot use block_key because we need block number serialized in sizeof(BlockUpperBound) bytes
    Bytes last_shard_suffix{upper_bound_suffix(std::numeric_limits<BlockUpperBound>::max())};

    const size_t optimal_shard_size{
        max_value_size_for_leaf_page(*txn, key_size + /*shard upper_bound*/ sizeof(BlockUpperBound))};

    PooledCursor target(txn, index_config_);
    datastore::kvdb::LoadFunc load_func{[&last_shard_suffix, &optimal_shard_size](
                                            const datastore::etl::Entry& entry,
                                            RWCursorDupSort& index_cursor,
                                            MDBX_put_flags_t put_flags) -> void {
        auto new_bitmap{parse_impl<RoaringMap>(entry.value)};  // Bitmap being merged

        // Check whether we have any previous shard to merge with
        Bytes shard_key{
            entry.key
                .substr(0, entry.key.size() - sizeof(uint16_t)) /* remove etl ordering suffix */
                .append(last_shard_suffix)};                    /* and append const suffix for last key */

        if (auto index_data{index_cursor.find(to_slice(shard_key), /*throw_notfound=*/false)}; index_data.done) {
            // Merge previous and current bitmap
            new_bitmap |= parse_impl<RoaringMap>(index_data.value);
            index_cursor.erase();  // Delete currently found record as it'll be rewritten
        }

        // Consume bitmap splitting in shards
        while (!new_bitmap.isEmpty()) {
            auto shard{cut_left_impl<RoaringMap>(new_bitmap, optimal_shard_size)};
            const bool consumed_to_last_chunk{new_bitmap.isEmpty()};
            const BlockUpperBound suffix{consumed_to_last_chunk ? std::numeric_limits<BlockUpperBound>::max() : shard.maximum()};
            intx::be::unsafe::store<BlockUpperBound>(&shard_key[shard_key.size() - sizeof(BlockUpperBound)], suffix);
            Bytes shard_bytes{to_bytes(shard)};
            mdbx::slice k{to_slice(shard_key)};
            mdbx::slice v{to_slice(shard_bytes)};
            mdbx::error::success_or_throw(index_cursor.put(k, &v, put_flags));
        }
    }};

    bitmaps_collector->load(target,
                            load_func,
                            target.empty() ? MDBX_put_flags_t::MDBX_APPEND : MDBX_put_flags_t::MDBX_UPSERT);
    bitmaps_collector->clear();
}

template <typename RoaringMap, typename BlockUpperBound>
void IndexLoader::unwind_bitmaps_impl(RWTxn& txn, BlockNum to, const std::map<Bytes, bool>& keys) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    PooledCursor target(txn, index_config_);
    for (const auto& [key, created] : keys) {
        // Log and abort check
        if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            if (SignalHandler::signalled()) {
                throw std::runtime_error("Operation cancelled");
            }

            std::scoped_lock log_lck{log_mtx_};
            current_key_ = abridge(to_hex(key, true), kAddressLength);
            log_time = now + 5s;
        }

        if (created) {
            // Key was created in the batch we're unwinding
            // Delete all its history
            cursor_erase_prefix(target, key);
            continue;
        }

        // Locate previous incomplete shard. There's always one if account has been touched at least once in changeset
        const Bytes shard_key{key + upper_bound_suffix(std::numeric_limits<BlockUpperBound>::max())};
        auto index_data{target.find(to_slice(shard_key), false)};
        while (index_data) {
            const auto index_data_key_view{from_slice(index_data.key)};
            if (!index_data_key_view.starts_with(key)) {
                break;
            }

            auto db_bitmap{parse_impl<RoaringMap>(index_data.value)};
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
            Bytes shard_bytes{to_bytes(db_bitmap)};
            target.insert(to_slice(shard_key), to_slice(shard_bytes));
            break;
        }
    }

    std::scoped_lock log_lck{log_mtx_};
    current_key_.clear();
}

void IndexLoader::merge_bitmaps32(RWTxn& txn, size_t key_size, datastore::kvdb::Collector* bitmaps_collector) {
    merge_bitmaps_impl<roaring::Roaring, uint32_t>(txn, key_size, bitmaps_collector);
}

void IndexLoader::merge_bitmaps(RWTxn& txn, size_t key_size, datastore::kvdb::Collector* bitmaps_collector) {
    merge_bitmaps_impl<roaring::Roaring64Map, uint64_t>(txn, key_size, bitmaps_collector);
}

void IndexLoader::unwind_bitmaps32(RWTxn& txn, BlockNum to, const std::map<Bytes, bool>& keys) {
    unwind_bitmaps_impl<roaring::Roaring, uint32_t>(txn, to, keys);
}

void IndexLoader::unwind_bitmaps(RWTxn& txn, BlockNum to, const std::map<Bytes, bool>& keys) {
    unwind_bitmaps_impl<roaring::Roaring64Map, uint64_t>(txn, to, keys);
}

template <typename RoaringMap, typename BlockUpperBound>
void IndexLoader::prune_bitmaps_impl(RWTxn& txn, BlockNum threshold) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    PooledCursor target(txn, index_config_);
    auto target_data{target.to_first(/*throw_notfound=*/false)};
    while (target_data) {
        const auto data_key_view{from_slice(target_data.key)};
        // Log and abort check
        if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            if (SignalHandler::signalled()) {
                throw std::runtime_error("Operation cancelled");
            }
            std::scoped_lock log_lck{log_mtx_};
            current_key_ = abridge(to_hex(data_key_view, true), kAddressLength);
            log_time = now + 5s;
        }

        // Suffix indicates the upper bound of the shard.
        ensure(data_key_view.size() >= sizeof(BlockUpperBound), [&]() { return "invalid key size " + std::to_string(data_key_view.size()); });
        const auto suffix{intx::be::unsafe::load<BlockUpperBound>(&data_key_view[data_key_view.size() - sizeof(BlockUpperBound)])};

        // If below pruning threshold simply delete the record
        if (suffix <= threshold) {
            target.erase();
        } else {
            // Read current bitmap
            auto bitmap{parse_impl<RoaringMap>(target_data.value)};
            bool shard_shrunk{false};
            while (!bitmap.isEmpty() && bitmap.minimum() <= threshold) {
                bitmap.remove(bitmap.minimum());
                shard_shrunk = true;
            }
            if (bitmap.isEmpty() || shard_shrunk) {
                if (!bitmap.isEmpty()) {
                    Bytes new_shard_data{to_bytes(bitmap)};
                    target.update(to_slice(data_key_view), to_slice(new_shard_data));
                } else {
                    target.erase();
                }
            }
        }

        target_data = target.to_next(/*throw_notfound=*/false);
    }

    std::scoped_lock log_lck{log_mtx_};
    current_key_.clear();
}

void IndexLoader::prune_bitmaps32(RWTxn& txn, BlockNum threshold) {
    prune_bitmaps_impl<roaring::Roaring, uint32_t>(txn, threshold);
}

void IndexLoader::prune_bitmaps(RWTxn& txn, BlockNum threshold) {
    prune_bitmaps_impl<roaring::Roaring64Map, uint64_t>(txn, threshold);
}

template <typename RoaringMap>
void flush_bitmaps_impl(absl::btree_map<Bytes, RoaringMap>& bitmaps, datastore::etl::Collector* collector, uint16_t flush_count) {
    for (auto& [key, bitmap] : bitmaps) {
        Bytes etl_key(key.size() + sizeof(uint16_t), '\0');
        std::memcpy(&etl_key[0], key.data(), key.size());
        endian::store_big_u16(&etl_key[key.size()], flush_count);
        collector->collect({etl_key, to_bytes(bitmap)});
    }
    bitmaps.clear();
}

void IndexLoader::flush_bitmaps_to_etl(absl::btree_map<Bytes, roaring::Roaring64Map>& bitmaps,
                                       datastore::etl::Collector* collector, uint16_t flush_count) {
    flush_bitmaps_impl(bitmaps, collector, flush_count);
}

void IndexLoader::flush_bitmaps_to_etl(absl::btree_map<Bytes, roaring::Roaring>& bitmaps,
                                       datastore::etl::Collector* collector, uint16_t flush_count) {
    flush_bitmaps_impl(bitmaps, collector, flush_count);
}

std::optional<uint64_t> seek(const roaring::Roaring64Map& bitmap, uint64_t n) {
    auto it{bitmap.begin()};
    if (it.move(n)) {
        return *it;
    }
    return std::nullopt;
}

roaring::Roaring cut_left(roaring::Roaring& bitmap, uint64_t size_limit) {
    return cut_left_impl(bitmap, size_limit);
}

roaring::Roaring64Map cut_left(roaring::Roaring64Map& bitmap, uint64_t size_limit) {
    return cut_left_impl(bitmap, size_limit);
}

template <typename RoaringMap>
Bytes bitmap_to_bytes(RoaringMap& bitmap) {
    if (!bitmap.isEmpty()) {
        Bytes ret(bitmap.getSizeInBytes(), '\0');
        bitmap.write(byte_ptr_cast(&ret[0]));
        return ret;
    }
    return {};
}

Bytes to_bytes(roaring::Roaring64Map& bitmap) {
    return bitmap_to_bytes(bitmap);
}

Bytes to_bytes(roaring::Roaring& bitmap) {
    return bitmap_to_bytes(bitmap);
}

roaring::Roaring64Map parse(const mdbx::slice& data) {
    return parse_impl<roaring::Roaring64Map>(data);
}

roaring::Roaring64Map parse(const ByteView data) {
    return parse_impl<roaring::Roaring64Map>(data);
}

roaring::Roaring parse32(const mdbx::slice& data) {
    return parse_impl<roaring::Roaring>(data);
}

}  // namespace silkworm::datastore::kvdb::bitmap
