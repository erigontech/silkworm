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

#include <functional>
#include <tuple>
#include <vector>

#include <silkworm/core/common/bytes.hpp>

#include "../seg/decompressor.hpp"

namespace silkworm::snapshots::btree {

class BTree {
  public:
    using DataIterator = seg::Decompressor::Iterator;
    using DataIndex = uint64_t;
    using KeyValue = std::pair<Bytes, Bytes>;
    using LookupResult = std::pair<bool, KeyValue>;
    using DataLookup = std::function<LookupResult(DataIndex, DataIterator&)>;
    using CompareResult = std::pair<int, Bytes>;
    using KeyCompare = std::function<CompareResult(ByteView, DataIndex, DataIterator&)>;

    using SeekResult = std::tuple<bool, Bytes, Bytes, DataIndex>;
    using GetResult = std::tuple<bool, Bytes, DataIndex>;

    BTree(uint64_t num_nodes,
          uint64_t fanout,
          DataLookup data_lookup,
          KeyCompare compare_key,
          DataIterator& data_it,
          std::span<uint8_t> encoded_nodes = {});

    //! \brief Search and return first key-value pair w/ key greater than or equal to \p seek_key
    //! \param seek_key the key to look for
    //! \param data_it an iterator to the key-value data sequence
    //! \return tuple (found, key, value, data index)
    //! \verbatim
    //! - found is true iff exact key match is encountered
    //! - if seek_key is empty, return first key and found=true
    //! - if found item.key has \p seek_key as prefix, return found=false and item.key
    //! - if key is greater than all keys, return found=false and empty key
    //! \endverbatim
    SeekResult seek(ByteView seek_key, DataIterator& data_it);

    //! \brief Search and return key equal to the given \p key
    //! \param key the key to look for
    //! \param data_it an iterator to the key-value data sequence
    //! \return tuple (found, key, data index)
    //! \verbatim
    //! - found is true iff exact key match is encountered
    //! \endverbatim
    GetResult get(ByteView key, DataIterator& data_it);

  protected:
    struct Node {
        DataIndex key_index{0};
        Bytes key;

        static std::pair<Node, size_t> from_encoded_data(std::span<uint8_t> encoded_node);
    };
    using Nodes = std::vector<Node>;
    using BinarySearchResult = std::tuple<Node*, uint64_t, uint64_t>;

    void warmup(DataIterator& data_it);
    void decode_nodes(std::span<uint8_t> encoded_nodes, DataIterator& data_it);

    BinarySearchResult binary_search_in_cache(ByteView key);

    //! The total number of nodes in the B-Tree index (most of them are only in file, not in cache)
    uint64_t num_nodes_;

    //! The number of children for each node in the B-Tree (often identified as M)
    uint64_t fanout_;

    //! The function called to obtain data key-value from data index
    DataLookup data_lookup_;

    //! The function called to compare keys
    KeyCompare compare_key_;

    //! The part of B-Tree nodes held in memory
    Nodes cache_;

    //! Flag indicating if encoded node keys must be checked against data keys
    bool check_encoded_keys_;
};

}  // namespace silkworm::snapshots::btree
