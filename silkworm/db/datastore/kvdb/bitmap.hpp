// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <absl/container/btree_map.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

// ignore a warning on a GCC release build:
// "accessing 9223372036854775810 or more bytes at offsets [2, 9223372036854775807] and 1 may overlap up to 9223372036854775813 bytes at offset -3"
// here: https://github.com/RoaringBitmap/CRoaring/blob/v1.1.2/cpp/roaring64map.hh#L1589
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wrestrict"
#endif

#include <roaring/roaring64map.hh>
#pragma GCC diagnostic pop

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

#include "mdbx.hpp"

namespace silkworm::datastore::etl {
class Collector;
}

namespace silkworm::datastore::kvdb {
class Collector;
}

namespace silkworm::datastore::kvdb::bitmap {

class IndexLoader {
  public:
    explicit IndexLoader(const MapConfig& index_config) : index_config_{index_config} {}

    //! \brief Merges a list of bitmaps, previously collected, into index table ensuring
    //! all bitmaps are properly sharded and that last bitmap is marked with an UINT64_MAX upper bound
    //! \param txn [in] : An MDBX transaction holder
    //! \param key_size [in] : The actual length of key in the list of bitmap shards (the index)
    //! \param bitmaps_collector [in] : A pointer to the datastore::etl::collector holding the bitmaps to be merged
    void merge_bitmaps(RWTxn& txn, size_t key_size, datastore::kvdb::Collector* bitmaps_collector);
    void merge_bitmaps32(RWTxn& txn, size_t key_size, datastore::kvdb::Collector* bitmaps_collector);

    //! \brief Provided a list of keys for which the unwind should be applied this removes right values from shards
    //! \param txn [in] : An MDBX transaction holder
    //! \param to [in] : The block number we should unwind index to
    //! \param keys [in] : The keys of index we should unwind
    void unwind_bitmaps(RWTxn& txn, BlockNum to, const std::map<Bytes, bool>& keys);
    void unwind_bitmaps32(RWTxn& txn, BlockNum to, const std::map<Bytes, bool>& keys);

    //! \brief Traverses all the index and for each bitmap removes left values <= threshold
    //! \param txn [in] : An MDBX transaction holder
    //! \param threshold [in] : The block number before which bitmaps values need to be pruned
    void prune_bitmaps(RWTxn& txn, BlockNum threshold);
    void prune_bitmaps32(RWTxn& txn, BlockNum threshold);

    //! \brief Returns the hex representation of currently processed key
    std::string get_current_key() const {
        std::scoped_lock lock{log_mtx_};
        return current_key_;
    }

    //! \brief Flushes a collected map of Bitmaps into an datastore::etl::Collector taking care of proper keys sorting for subsequent load
    //! \param bitmaps [in] : A map of keys and related bitmaps
    //! \param collector [in] : The collector to flush to
    //! \param flush_count [in]
    //! \remark Etl collector will sort and process entries lexicographically (using both key and value) for this reason
    //! we add flush_count as suffix of key, so we ensure for same account we process entries in the order
    //! they've been collected. uint16_t maxes 65K flushes
    static void flush_bitmaps_to_etl(absl::btree_map<Bytes, roaring::Roaring64Map>& bitmaps,
                                     datastore::etl::Collector* collector, uint16_t flush_count);
    static void flush_bitmaps_to_etl(absl::btree_map<Bytes, roaring::Roaring>& bitmaps,
                                     datastore::etl::Collector* collector, uint16_t flush_count);

  private:
    template <typename RoaringMap, typename BlockUpperBound>
    void merge_bitmaps_impl(RWTxn& txn, size_t key_size, datastore::kvdb::Collector* bitmaps_collector);

    template <typename RoaringMap, typename BlockUpperBound>
    void unwind_bitmaps_impl(RWTxn& txn, BlockNum to, const std::map<Bytes, bool>& keys);

    template <typename RoaringMap, typename BlockUpperBound>
    void prune_bitmaps_impl(RWTxn& txn, BlockNum threshold);

    const MapConfig& index_config_;  // The bucket config holding the index of maps
    mutable std::mutex log_mtx_;     // To get progress status
    std::string current_key_;        // Key being processed
};

// Return the first value in the bitmap that is not less than (i.e. greater or equal to) n,
// or std::nullopt if no such element is found.
// See Erigon SeekInBitmap64.
std::optional<uint64_t> seek(const roaring::Roaring64Map& bitmap, uint64_t n);

// Remove from a bitmap and return its biggest left part not exceeding a given size
roaring::Roaring64Map cut_left(roaring::Roaring64Map& bitmap, uint64_t size_limit);

// Remove from a bitmap and return its biggest left part not exceeding a given size
roaring::Roaring cut_left(roaring::Roaring& bitmap, uint64_t size_limit);

//! \brief Return bytes of Roaring64Map data
Bytes to_bytes(roaring::Roaring64Map& bitmap);

//! \brief Return bytes of Roaring data
Bytes to_bytes(roaring::Roaring& bitmap);

//! \brief Parse 64-bit roaring bitmap from MDBX slice
roaring::Roaring64Map parse(const mdbx::slice& data);

//! \brief Parse 64-bit roaring bitmap from ByteView
roaring::Roaring64Map parse(ByteView data);

//! \brief Parse 32-bit roaring bitmap from MDBX slice
roaring::Roaring parse32(const mdbx::slice& data);

}  // namespace silkworm::datastore::kvdb::bitmap
