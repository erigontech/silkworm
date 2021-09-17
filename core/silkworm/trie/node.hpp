/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_TRIE_NODE_HPP_
#define SILKWORM_TRIE_NODE_HPP_

#include <cassert>
#include <optional>
#include <vector>

#include <silkworm/common/base.hpp>

namespace silkworm::trie {

// Used in node/silkworm/trie/intermediate_hashes.hpp
//
// Presumed invariants:
// 1) tree_mask ⊆ state_mask
// 2) hash_mask ⊆ state_mask
// 3) #hash_mask == #hashes
class Node {
  public:
    Node(uint16_t state_mask, uint16_t tree_mask, uint16_t hash_mask, std::vector<evmc::bytes32> hashes,
         const std::optional<evmc::bytes32>& root_hash = std::nullopt);

    // copyable
    Node(const Node& other) = default;
    Node& operator=(const Node& other) = default;

    uint16_t state_mask() const { return state_mask_; }
    uint16_t tree_mask() const { return tree_mask_; }
    uint16_t hash_mask() const { return hash_mask_; }

    const std::vector<evmc::bytes32>& hashes() const { return hashes_; }

    const std::optional<evmc::bytes32>& root_hash() const { return root_hash_; }

    void set_root_hash(const std::optional<evmc::bytes32>& root_hash);

  private:
    uint16_t state_mask_{0};
    uint16_t tree_mask_{0};
    uint16_t hash_mask_{0};
    std::vector<evmc::bytes32> hashes_{};
    std::optional<evmc::bytes32> root_hash_{std::nullopt};
};

bool operator==(const Node& a, const Node& b);

// Erigon MarshalTrieNode
Bytes marshal_node(const Node& n);

// Erigon UnmarshalTrieNode
std::optional<Node> unmarshal_node(ByteView v);

inline void assert_subset(uint16_t sub, uint16_t sup) {
    auto intersection{sub & sup};
    assert(intersection == sub);
    (void)intersection;
}

}  // namespace silkworm::trie

#endif  // SILKWORM_TRIE_NODE_HPP_
