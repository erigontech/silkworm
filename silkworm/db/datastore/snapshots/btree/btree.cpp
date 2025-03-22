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

#include "btree.hpp"

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::snapshots::btree {

//! Smallest shard available for scan instead of binary search
static constexpr uint64_t kDefaultBtreeStartSkip{4};

BTree::BTree(
    uint64_t num_nodes,
    uint64_t fanout,
    std::span<uint8_t> encoded_nodes)
    : num_nodes_(num_nodes),
      fanout_{fanout},
      cache_{decode_nodes(encoded_nodes)} {
}

using CompareResult = std::pair<int, Bytes>;

static CompareResult compare_key(
    ByteView key,
    BTree::DataIndex key_index,
    const BTree::KeyValueIndex& index) {
    auto data_key = index.lookup_key(key_index);
    ensure(data_key.has_value(), [&]() { return "out-of-bounds key=" + to_hex(key) + " data_index=" + std::to_string(key_index); });
    int cmp = data_key->compare(key);
    return {cmp, std::move(*data_key)};
}

static BTree::KeyValueIndex::LookupResult lookup_key_value(
    ByteView key,
    BTree::DataIndex key_index,
    const BTree::KeyValueIndex& index) {
    BTree::KeyValueIndex::LookupResult result = index.lookup_key_value(key_index, key);
    ensure(result.key.has_value(), [&]() { return "out-of-bounds key=" + to_hex(key) + " data_index=" + std::to_string(key_index); });
    return result;
}

BTree::SeekResult BTree::seek(ByteView seek_key, const KeyValueIndex& index) {
    if (seek_key.empty() && num_nodes_ > 0) {
        auto kv_pair = index.lookup_key_value(0);
        if (!kv_pair) {
            return {/*found=*/false, {}, {}, 0};
        }
        bool found = kv_pair->first == seek_key;
        return {found, std::move(kv_pair->first), std::move(kv_pair->second), 0};
    }
    auto [_, left_index, right_index] = binary_search_in_cache(seek_key);  // left_index == right_index when key is found
    uint64_t median = 0;
    while (left_index < right_index) {
        if (right_index - left_index <= kDefaultBtreeStartSkip) {  // found small range, faster to scan now
            const auto [cmp, key] = compare_key(seek_key, left_index, index);
            if (cmp == 0) {
                right_index = left_index;
                break;
            }
            if (cmp < 0) {  // found key is greater than seek_key
                if (left_index + 1 < num_nodes_) {
                    ++left_index;
                    continue;
                }
            }
            right_index = left_index;
            break;
        }
        median = (left_index + right_index) >> 1;
        const auto [cmp, key] = compare_key(seek_key, median, index);
        if (cmp == 0) {
            left_index = right_index = median;
            break;
        }
        if (cmp > 0) {
            right_index = median;
        } else {
            left_index = median + 1;
        }
    }
    if (left_index == right_index) {
        median = left_index;
    }
    auto kv_pair = index.lookup_key_value(median);
    if (!kv_pair) {
        return {/*found=*/false, {}, {}, 0};
    }
    bool found = kv_pair->first == seek_key;
    return {found, std::move(kv_pair->first), std::move(kv_pair->second), left_index};
}

std::optional<BTree::GetResult> BTree::get(ByteView key, const KeyValueIndex& index) {
    if (key.empty() && num_nodes_ > 0) {
        auto kv_pair = index.lookup_key_value(0);
        if (!kv_pair) {
            return std::nullopt;
        }
        bool found = kv_pair->first == key;
        if (!found) {
            return std::nullopt;
        }
        return GetResult{std::move(kv_pair->second), 0};
    }
    auto [_, left_index, right_index] = binary_search_in_cache(key);  // left_index == right_index when key is found
    while (left_index < right_index) {
        const uint64_t median = (left_index + right_index) >> 1;
        auto [cmp, k, optional_v] = lookup_key_value(key, median, index);
        if (cmp == 0) {
            SILKWORM_ASSERT(optional_v);
            return GetResult{std::move(*optional_v), median};
        }
        if (cmp > 0) {
            right_index = median;
        } else {  // cmp < 0
            left_index = median + 1;
        }
    }
    auto [cmp, k, optional_v] = lookup_key_value(key, left_index, index);
    if (cmp != 0) {
        return std::nullopt;
    }
    SILKWORM_ASSERT(optional_v);
    return GetResult{std::move(*optional_v), left_index};
}

std::pair<BTree::Node, size_t> BTree::Node::from_encoded_data(std::span<uint8_t> encoded_node) {
    constexpr size_t kEncodedIndexPlusKeyLengthSize{sizeof(uint64_t) + sizeof(uint16_t)};
    ensure(encoded_node.size() >= kEncodedIndexPlusKeyLengthSize, "snapshots::index::BTree invalid encoded node size");
    const auto key_index = endian::load_big_u64(encoded_node.data());
    const auto encoded_key = encoded_node.subspan(sizeof(uint64_t));
    const auto key_length = endian::load_big_u16(encoded_key.data());
    const auto encoded_size = kEncodedIndexPlusKeyLengthSize + key_length;
    ensure(encoded_node.size() >= encoded_size, "snapshots::index::BTree invalid encoded node size");
    const auto key = encoded_key.subspan(sizeof(uint16_t), key_length);
    return {Node{key_index, Bytes{key.data(), key.size()}}, encoded_size};
}

void BTree::warmup(const KeyValueIndex& index) {
    if (num_nodes_ == 0) {
        return;
    }
    cache_.reserve(num_nodes_ / fanout_);

    uint64_t cached_bytes{0};
    const size_t step = num_nodes_ < fanout_ ? 1 : fanout_;  // cache all keys if less than M
    for (size_t i{step}; i < num_nodes_; i += step) {
        const size_t data_index = i - 1;
        auto [_, key] = compare_key({}, data_index, index);
        cache_.emplace_back(Node{data_index, Bytes{key}});
        cached_bytes += sizeof(Node) + key.length();
    }
    SILK_DEBUG << "BTree::warmup finished M=" << fanout_ << " N=" << num_nodes_ << " cache_size=" << cached_bytes;
}

BTree::Nodes BTree::decode_nodes(std::span<uint8_t> encoded_nodes) {
    if (encoded_nodes.empty())
        return {};
    BTree::Nodes nodes;

    ensure(encoded_nodes.size() >= sizeof(uint64_t), "snapshots::index::BTree invalid encoded list of nodes");
    const uint64_t node_count = endian::load_big_u64(encoded_nodes.data());
    nodes.reserve(node_count);

    size_t data_position{sizeof(uint64_t)};
    for (size_t n{0}; n < node_count; ++n) {
        auto [node, node_size] = Node::from_encoded_data(encoded_nodes.subspan(data_position));
        nodes.emplace_back(std::move(node));
        data_position += node_size;
    }

    return nodes;
}

void BTree::check_against_data_keys(const KeyValueIndex& index) {
    for (const auto& node : cache_) {
        const auto [cmp, key] = compare_key(node.key, node.key_index, index);
        ensure(cmp == 0, [&]() {
            return "key mismatch node.key=" + to_hex(node.key) +
                   " key=" + to_hex(key) +
                   " key_index=" + std::to_string(node.key_index);
        });
    }
}

BTree::BinarySearchResult BTree::binary_search_in_cache(ByteView key) {
    uint64_t left_index = 0, right_index = num_nodes_;
    uint64_t left_pos = 0, right_pos = cache_.size();
    BTree::Node* node{nullptr};
    while (left_pos < right_pos) {
        uint64_t median_pos = (left_pos + right_pos) >> 1;
        node = &cache_[median_pos];
        const int result = node->key.compare(key);
        if (result == 0) {
            return {node, node->key_index, node->key_index};
        }
        if (result > 0) {
            right_pos = median_pos;
            right_index = node->key_index;
        } else {  // result < 0
            left_pos = median_pos + 1;
            left_index = node->key_index;
        }
    }
    return {node, left_index, right_index};
}

}  // namespace silkworm::snapshots::btree
