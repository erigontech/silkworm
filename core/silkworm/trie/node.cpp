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

#include "node.hpp"

#include <bitset>

#include <silkworm/common/endian.hpp>

namespace silkworm::trie {

Node::Node(uint16_t state_mask, uint16_t tree_mask, uint16_t hash_mask, std::vector<evmc::bytes32> hashes,
           const std::optional<evmc::bytes32>& root_hash)
    : state_mask_{state_mask},
      tree_mask_{tree_mask},
      hash_mask_{hash_mask},
      hashes_{std::move(hashes)},
      root_hash_{root_hash} {
    assert_subset(tree_mask_, state_mask_);
    assert_subset(hash_mask_, state_mask_);
    assert(std::bitset<16>(hash_mask_).count() == hashes_.size());
}

void Node::set_root_hash(const std::optional<evmc::bytes32>& root_hash) { root_hash_ = root_hash; }

bool operator==(const Node& a, const Node& b) {
    return a.state_mask() == b.state_mask() && a.tree_mask() == b.tree_mask() && a.hash_mask() == b.hash_mask() &&
           a.hashes() == b.hashes() && a.root_hash() == b.root_hash();
}

Bytes marshal_node(const Node& n) {
    size_t buf_size{/* 3 masks state/tree/hash 2 bytes each */ 6 +
                    /* root hash */ (n.root_hash().has_value() ? kHashLength : 0u) +
                    /* hashes */ n.hashes().size() * kHashLength};

    Bytes buf(buf_size, '\0');
    size_t pos{0};

    endian::store_big_u16(&buf[pos], n.state_mask());
    pos += 2;

    endian::store_big_u16(&buf[pos], n.tree_mask());
    pos += 2;

    endian::store_big_u16(&buf[pos], n.hash_mask());
    pos += 2;

    if (n.root_hash().has_value()) {
        std::memcpy(&buf[pos], n.root_hash()->bytes, kHashLength);
        pos += kHashLength;
    }

    for (const auto& hash : n.hashes()) {
        std::memcpy(&buf[pos], hash.bytes, kHashLength);
        pos += kHashLength;
    }

    return buf;
}

std::optional<Node> unmarshal_node(ByteView v) {
    if (v.length() < 6) {
        // At least state/tree/hash masks need to be present
        return std::nullopt;
    } else {
        // Beyond the 6th byte the length must be a multiple of kHashLength
        if ((v.length() - 6) % kHashLength != 0) {
            return std::nullopt;
        }
    }

    const auto state_mask{endian::load_big_u16(v.data())};
    v.remove_prefix(2);
    const auto tree_mask{endian::load_big_u16(v.data())};
    v.remove_prefix(2);
    const auto hash_mask{endian::load_big_u16(v.data())};
    v.remove_prefix(2);

    std::optional<evmc::bytes32> root_hash{std::nullopt};
    if (std::bitset<16>(hash_mask).count() + 1 == v.length() / kHashLength) {
        root_hash = evmc::bytes32{};
        std::memcpy(root_hash->bytes, v.data(), kHashLength);
        v.remove_prefix(kHashLength);
    }

    const size_t num_hashes{v.length() / kHashLength};
    std::vector<evmc::bytes32> hashes(num_hashes);
    for (size_t i{0}; i < num_hashes; ++i) {
        std::memcpy(hashes[i].bytes, v.data(), kHashLength);
        v.remove_prefix(kHashLength);
    }

    return Node{state_mask, tree_mask, hash_mask, hashes, root_hash};
}

}  // namespace silkworm::trie
