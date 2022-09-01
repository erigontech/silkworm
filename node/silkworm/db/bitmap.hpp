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

#pragma once

#include <optional>

#include <absl/container/btree_map.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <roaring64map.hh>
#pragma GCC diagnostic pop

#include <boost/functional/hash.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/db/mdbx.hpp>
#include <silkworm/etl/collector.hpp>

namespace silkworm::db::bitmap {

class IndexLoader {
  public:
    explicit IndexLoader(const db::MapConfig& index_config) : index_config_{index_config} {}

    //! \brief Merges a list of bitmaps, previously collected, into index table ensuring
    //! all bitmaps are properly sharded and that last bitmap is marked with an UINT64_MAX upper bound
    //! \param txn [in] : An MDBX transaction holder
    //! \param key_size [in] : The actual length of key in the list of bitmap shards (the index)
    //! \param collector [in] : A pointer to the etl::collector holding the bitmaps to be merged
    void merge_bitmaps(RWTxn& txn, size_t key_size, etl::Collector* bitmaps_collector);

    //! \brief Provided a list of keys for which the unwind should be applied this removes right values from shards
    //! \param txn [in] : An MDBX transaction holder
    //! \param to [in] : The block height we should unwind index to
    //! \param keys [in] : The keys of index we should unwind
    void unwind_bitmaps(RWTxn& txn, BlockNum to, const std::map<Bytes, bool>& keys);

    //! \brief Traverses all the index and for each bitmap removes left values <= threshold
    //! \param txn [in] : An MDBX transaction holder
    //! \param threshold [in] : The block height before which bitmaps values need to be pruned
    void prune_bitmaps(RWTxn& txn, BlockNum threshold);

    //! \brief Returns the hex representation of currently processed key
    [[nodiscard]] std::string get_current_key() const {
        std::unique_lock l{log_mtx_};
        return current_key_;
    }

    //! \brief Flushes a collected map of Bitmaps into an etl::Collector taking care of proper keys sorting
    //! for subsequent load
    //! \param bitmaps [in] : A map of keys and related bitmaps
    //! \param collector [in] : The collector to flush to
    //! \param flush_count [in]
    //! \remark Etl collector will sort and process entries lexicographically (using both key and value) for this reason
    //! we add flush_count as suffix of key, so we ensure for same account we process entries in the order
    //! they've been collected. uint16_t maxes 65K flushes
    static void flush_bitmaps_to_etl(absl::btree_map<Bytes, roaring::Roaring64Map>& bitmaps,
                                     etl::Collector* collector, uint16_t flush_count);

  private:
    const db::MapConfig& index_config_;  // The bucket config holding the index of maps
    mutable std::mutex log_mtx_;         // To get progress status
    std::string current_key_;            // Key being processed
};

// Return the first value in the bitmap that is not less than (i.e. greater or equal to) n,
// or std::nullopt if no such element is found.
// See Erigon SeekInBitmap64.
std::optional<uint64_t> seek(const roaring::Roaring64Map& bitmap, uint64_t n);

// Remove from a bitmap and return its biggest left part not exceeding a given size
roaring::Roaring64Map cut_left(roaring::Roaring64Map& bitmap, uint64_t size_limit);

// Remove from a bitmap and return its biggest left part not exceeding a given size
roaring::Roaring cut_left(roaring::Roaring& bitmap, uint64_t size_limit);

//! \brief Returns Bytes of Roaring64Map data
Bytes to_bytes(roaring::Roaring64Map& bitmap);

//! \brief Returns Roaring64Map from MDBX's slice;
roaring::Roaring64Map parse(const mdbx::slice& data);

//! \brief Returns Roaring64Map from Bytes/Byteview;
roaring::Roaring64Map parse(const ByteView data);

}  // namespace silkworm::db::bitmap
