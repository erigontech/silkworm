// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <vector>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/decoding_result.hpp>

namespace silkworm::trie {

// Used in node/silkworm/trie/intermediate_hashes.hpp
//
// Presumed invariants:
// 1) tree_mask ⊆ state_mask
// 2) hash_mask ⊆ state_mask
// 3) #hash_mask == #hashes
class Node {
  public:
    Node() = default;
    explicit Node(uint16_t state_mask, uint16_t tree_mask, uint16_t hash_mask, std::vector<evmc::bytes32> hashes,
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

    friend bool operator==(const Node&, const Node&) = default;

    //! \see Erigon's MarshalTrieNodeTyped
    Bytes encode_for_storage() const;

    //! \see Erigon's UnmarshalTrieNodeTyped
    static DecodingResult decode_from_storage(ByteView raw, Node& node);

  protected:
    uint16_t state_mask_{0};  // Each bit set indicates parenting of a hashed state
    uint16_t tree_mask_{0};   // Each bit set indicates parenting of a child
    uint16_t hash_mask_{0};   // Each bit set indicates ownership of a valid hash
    std::vector<evmc::bytes32> hashes_{};
    std::optional<evmc::bytes32> root_hash_{std::nullopt};

  private:
};

inline bool is_subset(uint16_t sub, uint16_t sup) { return (sub & sup) == sub; }

}  // namespace silkworm::trie
