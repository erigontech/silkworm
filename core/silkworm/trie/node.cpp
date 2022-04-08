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

#include <silkworm/common/endian.hpp>
#include <silkworm/common/util.hpp>

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
    assert(popcount_16(hash_mask_) == hashes_.size());
}

void Node::set_root_hash(const std::optional<evmc::bytes32>& root_hash) { root_hash_ = root_hash; }

bool operator==(const Node& a, const Node& b) {
    return a.state_mask() == b.state_mask() && a.tree_mask() == b.tree_mask() && a.hash_mask() == b.hash_mask() &&
           a.hashes() == b.hashes() && a.root_hash() == b.root_hash();
}

Bytes marshal_node(const Node& node) {
    size_t buf_size{/* 3 masks state/tree/hash 2 bytes each */ 6 +
                    /* root hash */ (node.root_hash().has_value() ? kHashLength : 0u) +
                    /* hashes */ node.hashes().size() * kHashLength};

    Bytes buf(buf_size, '\0');
    size_t pos{0};

    endian::store_big_u16(&buf[pos], node.state_mask());
    pos += 2;

    endian::store_big_u16(&buf[pos], node.tree_mask());
    pos += 2;

    endian::store_big_u16(&buf[pos], node.hash_mask());
    pos += 2;

    if (node.root_hash().has_value()) {
        std::memcpy(&buf[pos], node.root_hash()->bytes, kHashLength);
        pos += kHashLength;
    }

    std::memcpy(&buf[pos], node.hashes().data(), node.hashes().size() * kHashLength);
    return buf;
}

std::optional<Node> unmarshal_node(ByteView v) {
    // At least state/tree/hash masks need to be present
    if (v.length() < 6) {
        return std::nullopt;
    }
    // Beyond the 6th byte the length must be a multiple of kHashLength
    if ((v.length() - 6) % kHashLength != 0) {
        return std::nullopt;
    }

    const auto state_mask{endian::load_big_u16(v.data())};
    v.remove_prefix(2);
    const auto tree_mask{endian::load_big_u16(v.data())};
    v.remove_prefix(2);
    const auto hash_mask{endian::load_big_u16(v.data())};
    v.remove_prefix(2);

    std::optional<evmc::bytes32> root_hash{std::nullopt};
    size_t num_hashes{v.length() / kHashLength};
    if (popcount_16(hash_mask) + 1u == num_hashes) {
        root_hash = evmc::bytes32{};
        std::memcpy(root_hash->bytes, v.data(), kHashLength);
        v.remove_prefix(kHashLength);
        --num_hashes;
    }

    std::vector<evmc::bytes32> hashes(num_hashes);
    std::memcpy(hashes.data(), v.data(), v.length());

    return Node{state_mask, tree_mask, hash_mask, hashes, root_hash};
}

}  // namespace silkworm::trie
