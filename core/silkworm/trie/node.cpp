/*
   Copyright 2021-2022 The Silkworm Authors

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

Bytes Node::encode_for_storage() const {
    const size_t buf_size{/* 3 masks state/tree/hash 2 bytes each */ 6 +
                          /* root hash */ (root_hash_.has_value() ? kHashLength : 0u) +
                          /* hashes */ hashes_.size() * kHashLength};
    Bytes buf(buf_size, '\0');
    endian::store_big_u16(&buf[0], state_mask_);
    endian::store_big_u16(&buf[2], tree_mask_);
    endian::store_big_u16(&buf[4], hash_mask_);

    size_t pos{6};
    if (root_hash_.has_value()) {
        std::memcpy(&buf[pos], root_hash_->bytes, kHashLength);
        pos += kHashLength;
    }

    std::memcpy(&buf[pos], hashes_.data(), hashes_.size() * kHashLength);
    return buf;
}

std::optional<Node> Node::from_encoded_storage(ByteView raw) {
    // At least state/tree/hash masks need to be present
    if (raw.length() < 6) {
        return std::nullopt;
    }
    // Beyond the 6th byte the length must be a multiple of kHashLength
    if ((raw.length() - 6) % kHashLength != 0) {
        return std::nullopt;
    }

    const auto state_mask{endian::load_big_u16(&raw.data()[0])};
    const auto tree_mask{endian::load_big_u16(&raw.data()[2])};
    const auto hash_mask{endian::load_big_u16(&raw.data()[4])};
    raw.remove_prefix(6);

    std::optional<evmc::bytes32> root_hash{std::nullopt};
    size_t num_hashes{raw.length() / kHashLength};
    if (popcount_16(hash_mask) + 1u == num_hashes) {
        root_hash = evmc::bytes32{};
        std::memcpy(root_hash->bytes, raw.data(), kHashLength);
        raw.remove_prefix(kHashLength);
        --num_hashes;
    }

    std::vector<evmc::bytes32> hashes(num_hashes);
    std::memcpy(hashes.data(), raw.data(), raw.length());

    return Node{state_mask, tree_mask, hash_mask, hashes, root_hash};
}

bool operator==(const Node& a, const Node& b) {
    return a.state_mask() == b.state_mask() && a.tree_mask() == b.tree_mask() && a.hash_mask() == b.hash_mask() &&
           a.hashes() == b.hashes() && a.root_hash() == b.root_hash();
}


}  // namespace silkworm::trie
