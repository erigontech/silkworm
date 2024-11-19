/*
   Copyright 2024 The Silkworm Authors

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

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>

#include <silkworm/infra/common/memory_mapped_file.hpp>

#include "../elias_fano/elias_fano.hpp"
#include "../segment/seg/decompressor.hpp"
#include "btree.hpp"

namespace silkworm::snapshots::btree {

class BTreeIndex {
  public:
    static constexpr uint64_t kDefaultFanout{256};

    using DataIndex = BTree::DataIndex;
    using DataIterator = BTree::DataIterator;
    using EliasFanoList32 = elias_fano::EliasFanoList32;

    class Cursor {
      public:
        ByteView key() const noexcept { return key_; }
        ByteView value() const noexcept { return value_; }
        DataIndex data_index() const noexcept { return data_index_; }

        bool next();

      private:
        friend class BTreeIndex;

        Cursor(BTreeIndex* index, ByteView key, ByteView value, DataIndex data_index, DataIterator data_it);
        bool to_next();

        BTreeIndex* index_;
        Bytes key_;
        Bytes value_;
        DataIndex data_index_;
        DataIterator data_it_;
    };

    BTreeIndex(seg::Decompressor& kv_decompressor,
               std::filesystem::path index_file_path,
               std::optional<MemoryMappedRegion> index_region = {},
               uint64_t btree_fanout = kDefaultFanout);

    //! Return the Elias-Fano encoding of the sequence of key offsets or nullptr if not present
    const EliasFanoList32* data_offsets() const { return data_offsets_.get(); }

    //! Return the number of keys included into this index
    size_t key_count() const { return data_offsets_->sequence_length(); };

    //! Seek and return a cursor at position where key >= \p seek_key
    //! \param seek_key the given key at which the cursor must be seeked
    //! \param data_it an iterator to the key-value data sequence
    //! \return a cursor positioned at key >= \p seek_key or nullptr
    //! \details if \p seek_key is empty, first key is returned
    //! \details if \p seek_key is greater than any other key, std::nullopt is returned
    std::optional<Cursor> seek(ByteView seek_key, DataIterator data_it);

    //! Get the value associated to the given key with exact match
    //! \param key the data key to match exactly
    //! \param data_it an iterator to the key-value data sequence
    //! \return the value associated at \p key or std::nullopt if not found
    std::optional<Bytes> get(ByteView key, DataIterator data_it);

  private:
    Cursor new_cursor(ByteView key, ByteView value, DataIndex data_index, DataIterator data_it);

    BTree::LookupResult lookup_data(DataIndex data_index, DataIterator data_it);
    BTree::CompareResult compare_key(ByteView key, DataIndex data_index, DataIterator data_it);

    std::filesystem::path file_path_;
    std::unique_ptr<MemoryMappedFile> memory_file_;
    std::unique_ptr<EliasFanoList32> data_offsets_;
    std::unique_ptr<BTree> btree_;
};

}  // namespace silkworm::snapshots::btree
