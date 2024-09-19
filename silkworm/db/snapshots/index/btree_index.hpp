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

#include "../rec_split/encoding/elias_fano.hpp"  // TODO(canepat) move to snapshots/common
#include "../seg/decompressor.hpp"
#include "btree.hpp"

namespace silkworm::snapshots::index {

using rec_split::encoding::EliasFanoList32;  // TODO(canepat) remove after moving

class BTreeIndex {
  public:
    static constexpr auto kDefaultFanout{256};

    using DataIndex = BTree::DataIndex;
    using DataIterator = BTree::DataIterator;

    class Cursor {
      public:
        using iterator_category [[maybe_unused]] = std::input_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using value_type = std::tuple<ByteView, ByteView, DataIndex>;
        using pointer = value_type*;
        using reference = value_type&;

        // reference operator*() { return key_value_index_; }
        // pointer operator->() { return &key_value_index_; }

        Cursor& operator++() {
            next();
            return *this;
        }

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
        // value_type key_value_index_;
        DataIterator data_it_;
    };

    BTreeIndex(seg::Decompressor& kv_decompressor,
               std::filesystem::path index_file_path,
               std::optional<MemoryMappedRegion> index_region = {},
               uint64_t btree_fanout = kDefaultFanout);

    //! Return the Elias-Fano encoding of the sequence of key offsets or nullptr if not present
    const EliasFanoList32* data_offsets() const { return data_offsets_.get(); }

    //! Is this index empty or not?
    bool empty() const { return data_offsets_ ? data_offsets_->sequence_length() == 0 : true; }

    //! Return the number of keys included into this index
    size_t key_count() const { return data_offsets_ ? data_offsets_->sequence_length() : 0; };

    //! Seek and return cursor at position where key >= \p seek_key
    //! \param seek_key the given key to seek cursor at
    //! \return a cursor positioned at key >= \p seek_key
    //! \details if \p seek_key is empty, first key is returned
    //! \details if \p seek_key greater than any other key, nullptr is returned
    std::unique_ptr<Cursor> seek(ByteView seek_key, DataIterator data_it);

    //! Get the value associated to the given key with exact match
    std::optional<Bytes> get(ByteView key, DataIterator data_it);

  private:
    std::unique_ptr<Cursor> new_cursor(ByteView key, ByteView value, DataIndex data_index, DataIterator data_it);

    BTree::LookupResult lookup_data(DataIndex data_index, DataIterator data_it);
    BTree::CompareResult compare_key(ByteView key, DataIndex data_index, DataIterator data_it);

    std::filesystem::path file_path_;
    std::unique_ptr<MemoryMappedFile> memory_file_;
    std::unique_ptr<EliasFanoList32> data_offsets_;
    std::unique_ptr<BTree> btree_;
};

}  // namespace silkworm::snapshots::index
