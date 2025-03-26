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
#include <optional>
#include <vector>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::snapshots::btree {

class BTree {
  public:
    using DataIndex = uint64_t;
    using KeyValue = std::pair<BytesOrByteView, BytesOrByteView>;

    struct KeyValueIndex {
        virtual ~KeyValueIndex() = default;
        virtual std::optional<KeyValue> lookup_key_value(DataIndex) const = 0;
        virtual std::optional<BytesOrByteView> lookup_key(DataIndex) const = 0;

        using LookupResult = std::pair<int, std::optional<BytesOrByteView>>;
        virtual std::optional<LookupResult> lookup_key_value(DataIndex, ByteView) const = 0;
        virtual std::optional<BytesOrByteView> advance_key_value(DataIndex, ByteView, size_t skip_max_count) const = 0;
    };

    struct SeekResult {
        bool found{false};
        BytesOrByteView key;
        BytesOrByteView value;
        DataIndex key_index{0};
    };

    BTree(
        uint64_t num_nodes,
        uint64_t fanout,
        std::span<uint8_t> encoded_nodes);

    //! Build the cache from data using some heuristics
    void warmup(const KeyValueIndex& index);

    //! \brief Search and return first key-value pair w/ key greater than or equal to \p seek_key
    //! \param seek_key the key to look for
    //! \param index the key-value data sequence
    //! \verbatim
    //! - found is true if an exact key match is encountered
    //! - if seek_key is empty, it tries the first data index
    //! - if found item.key has \p seek_key as prefix, return found=false and item.key
    //! - if key is greater than all keys, return found=false and empty key
    //! \endverbatim
    SeekResult seek(ByteView seek_key, const KeyValueIndex& index);

    //! \brief Search and return key equal to the given \p key
    //! \param key the key to look for
    //! \param index the key-value data sequence
    std::optional<BytesOrByteView> get(ByteView key, const KeyValueIndex& index);

    void check_against_data_keys(const KeyValueIndex& index);

    bool empty() const { return cache_.empty(); }

  protected:
    struct Node {
        DataIndex key_index{0};
        Bytes key;

        static std::pair<Node, size_t> from_encoded_data(std::span<uint8_t> encoded_node);
    };
    using Nodes = std::vector<Node>;
    using BinarySearchResult = std::tuple<Node*, uint64_t, uint64_t>;

    static BTree::Nodes decode_nodes(std::span<uint8_t> encoded_nodes);

    BinarySearchResult binary_search_in_cache(ByteView key);

    //! The total number of nodes in the B-Tree index (most of them are only in file, not in cache)
    uint64_t num_nodes_;

    //! The number of children for each node in the B-Tree (often identified as M)
    uint64_t fanout_;

    //! The part of B-Tree nodes held in memory
    Nodes cache_;
};

}  // namespace silkworm::snapshots::btree
