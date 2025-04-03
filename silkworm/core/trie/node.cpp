// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "node.hpp"

#include <bit>
#include <utility>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/endian.hpp>

namespace silkworm::trie {

Node::Node(uint16_t state_mask, uint16_t tree_mask, uint16_t hash_mask, std::vector<evmc::bytes32> hashes,
           const std::optional<evmc::bytes32>& root_hash)
    : state_mask_{state_mask},
      tree_mask_{tree_mask},
      hash_mask_{hash_mask},
      hashes_{std::move(hashes)},
      root_hash_{root_hash} {
    SILKWORM_ASSERT(is_subset(tree_mask, state_mask));
    SILKWORM_ASSERT(is_subset(hash_mask, state_mask));
    SILKWORM_ASSERT(std::cmp_equal(std::popcount(hash_mask_), hashes_.size()));
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

    if (!hashes_.empty()) {
        std::memcpy(&buf[pos], hashes_.data(), hashes_.size() * kHashLength);
    }
    return buf;
}

DecodingResult Node::decode_from_storage(ByteView raw, Node& node) {
    // At least state/tree/hash masks need to be present
    if (raw.length() < 6) {
        return tl::unexpected{DecodingError::kInputTooShort};
    }
    // Beyond the 6th byte the length must be a multiple of kHashLength
    if ((raw.length() - 6) % kHashLength != 0) {
        return tl::unexpected{DecodingError::kInvalidHashesLength};
    }

    node.root_hash_.reset();
    node.hashes_.clear();
    node.state_mask_ = endian::load_big_u16(&raw[0]);
    node.tree_mask_ = endian::load_big_u16(&raw[2]);
    node.hash_mask_ = endian::load_big_u16(&raw[4]);

    if (!is_subset(node.tree_mask_, node.state_mask_) || !is_subset(node.hash_mask_, node.state_mask_)) {
        return tl::unexpected{DecodingError::kInvalidMasksSubsets};
    }

    raw.remove_prefix(6);

    size_t expected_num_hashes{static_cast<size_t>(std::popcount(node.hash_mask_))};
    size_t effective_num_hashes{raw.length() / kHashLength};

    if (effective_num_hashes < expected_num_hashes) {
        return tl::unexpected{DecodingError::kInvalidHashesLength};
    }

    size_t delta{effective_num_hashes - expected_num_hashes};
    if (delta > 1) {
        return tl::unexpected{DecodingError::kInvalidHashesLength};
    }
    if (delta == 1) {
        node.root_hash_.emplace();
        std::memcpy(node.root_hash_->bytes, raw.data(), kHashLength);
        raw.remove_prefix(kHashLength);
        --effective_num_hashes;
    }

    node.hashes_.resize(effective_num_hashes);
    if (effective_num_hashes) {
        std::memcpy(node.hashes_.data(), raw.data(), raw.length());
    }
    return {};
}

}  // namespace silkworm::trie
