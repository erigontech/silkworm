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
    //! \param mdbx_page_size [in] : The configured page size for underlying MDBX data
    //! \param key_size [in] : The actual length of key in the list of bitmap shards (the index)
    //! \param collector [in] : A pointer to the etl::collector holding the bitmaps to be merged
    void merge_bitmaps(RWTxn& txn, size_t mdbx_page_size, size_t key_size, etl::Collector* bitmaps_collector);

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

  private:
    const db::MapConfig& index_config_;  // The bucket config holding the index of maps
    mutable std::mutex log_mtx_;         // To get progress status
    std::string current_key_;            // Key being processed

    //! \brief Determines optimal bitmap shard size on behalf of MDBX's page size to have leaf nodes
    //! filled at maximum without generating overflow pages
    [[nodiscard]] size_t compute_optimal_bitmap_shard_size(const size_t mdbx_page_size, const size_t shard_key_size);
};

// Erigon bitmapdb.ChunkLimit
// Value is obtained as threshold beyond which MDBX overflow pages : i.e. 4096 / 2 - (keySize + 8)
// TODO Adjust for case when pagesize is 8192
inline constexpr size_t kBitmapChunkLimit = 1950;

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
