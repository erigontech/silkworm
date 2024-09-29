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

#include <boost/process/environment.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::snapshots::index {

//! Smallest shard available for scan instead of binary search
static constexpr uint64_t kDefaultBtreeStartSkip{4};

static bool enable_assert_btree_keys() {
    bool enabled{false};
    auto environment = boost::this_process::environment();
    const auto env_var = environment["BT_ASSERT_OFFSETS"];
    if (!env_var.empty()) {
        enabled = std::stoul(env_var.to_string()) != 0;
    }
    return enabled;
}

BTree::BTree(uint64_t num_nodes,
             uint64_t fanout,
             DataLookup data_lookup,
             KeyCompare compare_key,
             DataIterator& data_it,
             std::span<uint8_t> encoded_nodes)
    : num_nodes_(num_nodes),
      fanout_{fanout},
      data_lookup_{std::move(data_lookup)},
      compare_key_{std::move(compare_key)},
      check_encoded_keys_(enable_assert_btree_keys()) {
    if (encoded_nodes.empty()) {
        // Build the cache from data using some heuristics
        warmup(data_it);
    } else {
        // Materialize the cache from its encoded representation
        decode_nodes(encoded_nodes, data_it);
    }
}

BTree::SeekResult BTree::seek(ByteView seek_key, DataIterator& data_it) {
    if (seek_key.empty() && num_nodes_ > 0) {
        const auto [found, kv_pair] = data_lookup_(0, data_it);
        if (!found) {
            return {/*found=*/false, {}, {}, 0};
        }
        return {kv_pair.first == seek_key, kv_pair.first, kv_pair.second, 0};
    }
    auto [_, left_index, right_index] = binary_search_in_cache(seek_key);  // left_index == right_index when key is found
    uint64_t median = 0;
    while (left_index < right_index) {
        if (right_index - left_index <= kDefaultBtreeStartSkip) {  // found small range, faster to scan now
            const auto [cmp, key] = compare_key_(seek_key, left_index, data_it);
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
        const auto [cmp, key] = compare_key_(seek_key, median, data_it);
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
    const auto [found, kv_pair] = data_lookup_(median, data_it);
    if (!found) {
        return {/*found=*/false, {}, {}, 0};
    }
    return {kv_pair.first == seek_key, kv_pair.first, kv_pair.second, left_index};
}

BTree::GetResult BTree::get(ByteView key, DataIterator& data_it) {
    if (key.empty() && num_nodes_ > 0) {
        const auto [found, kv_pair] = data_lookup_(0, data_it);
        if (!found) {
            return {/*found=*/false, {}, 0};
        }
        return {kv_pair.first == key, kv_pair.first, 0};
    }
    auto [_, left_index, right_index] = binary_search_in_cache(key);  // left_index == right_index when key is found
    uint64_t median = 0;
    while (left_index < right_index) {
        median = (left_index + right_index) >> 1;
        const auto [cmp, k] = compare_key_(key, median, data_it);
        switch (cmp) {
            case 0:
                return {/*found=*/true, k, median};
            case 1:
                right_index = median;
                break;
            case -1:
                left_index = median + 1;
                break;
            default:
                SILKWORM_ASSERT(false);
        }
    }
    auto [cmp, k] = compare_key_(key, left_index, data_it);
    if (cmp != 0) {
        return {/*found=*/false, {}, 0};
    }
    return {/*found=*/true, std::move(k), left_index};
}

std::pair<BTree::Node, size_t> BTree::Node::from_encoded_data(std::span<uint8_t> encoded_node) {
    constexpr size_t kEncodedIndexPlusKeyLengthSize{sizeof(uint64_t) + sizeof(uint16_t)};
    ensure(encoded_node.size() >= kEncodedIndexPlusKeyLengthSize, "snapshots::index::BTree invalid encoded node size");
    const auto key_index = endian::load_big_u64(encoded_node.data());
    const auto encoded_key = encoded_node.subspan(sizeof(uint64_t));
    const auto key_length = endian::load_big_u16(encoded_key.data());
    const auto encoded_size = kEncodedIndexPlusKeyLengthSize + key_length;
    ensure(encoded_node.size() >= encoded_size, "snapshots::index::BTree invalid encoded node size");
    const auto key = encoded_key.subspan(sizeof(uint16_t));
    return {Node{key_index, Bytes{key.data(), key.size()}}, encoded_size};
}

void BTree::warmup(DataIterator& data_it) {
    if (num_nodes_ == 0) {
        return;
    }
    cache_.reserve(num_nodes_ / fanout_);

    uint64_t cached_bytes{0};
    const size_t step = num_nodes_ < fanout_ ? 1 : fanout_;  // cache all keys if less than M
    for (size_t i{step}; i < num_nodes_; i += step) {
        const size_t data_index = i - 1;
        auto [_, key] = compare_key_({}, data_index, data_it);
        cache_.emplace_back(Node{data_index, Bytes{key}});
        cached_bytes += sizeof(Node) + key.length();
    }
    SILK_DEBUG << "BTree::warmup finished M=" << fanout_ << " N=" << num_nodes_ << " cache_size=" << cached_bytes;
}

void BTree::decode_nodes(std::span<uint8_t> encoded_nodes, DataIterator& data_it) {
    ensure(encoded_nodes.size() >= sizeof(uint64_t), "snapshots::index::BTree invalid encoded list of nodes");

    const uint64_t node_count = endian::load_big_u64(encoded_nodes.data());
    cache_.reserve(node_count);

    size_t data_position{sizeof(uint64_t)};
    for (size_t n{0}; n < node_count; ++n) {
        auto [node, node_size] = Node::from_encoded_data(encoded_nodes.subspan(data_position));
        if (check_encoded_keys_) {
            const auto [cmp, key] = compare_key_(node.key, node.key_index, data_it);
            ensure(cmp == 0, [&]() { return "key mismatch node.key=" + to_hex(node.key) + " key=" + to_hex(key) +
                                            " n=" + std::to_string(n) + " key_index=" + std::to_string(node.key_index); });
        }
        cache_.emplace_back(std::move(node));
        data_position += node_size;
    }
}

BTree::BinarySearchResult BTree::binary_search_in_cache(ByteView key) {
    uint64_t left_index = 0, right_index = num_nodes_;
    uint64_t left_pos = 0, right_pos = cache_.size();
    BTree::Node* node{nullptr};
    while (left_pos < right_pos) {
        uint64_t median_pos = (left_pos + right_pos) >> 1;
        node = &cache_[median_pos];
        switch (node->key.compare(key)) {
            case 0:
                return {node, node->key_index, node->key_index};
            case 1:
                right_pos = median_pos;
                right_index = node->key_index;
                break;
            case -1:
                left_pos = median_pos + 1;
                left_index = node->key_index;
                break;
            default:
                SILKWORM_ASSERT(false);
        }
    }
    return {node, left_index, right_index};
}

}  // namespace silkworm::snapshots::index
