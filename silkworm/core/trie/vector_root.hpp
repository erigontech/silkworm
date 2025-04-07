// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <concepts>
#include <functional>

#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/trie/hash_builder.hpp>
#include <silkworm/core/trie/nibbles.hpp>

namespace silkworm::trie {

// Lexicographic order for RLP-encoded integers is the same as their natural order,
// save for 0, which, due to its RLP encoding, should be placed between 0x7f and 0x80.
inline size_t adjust_index_for_rlp(size_t i, size_t len) {
    if (i > 0x7f) {
        return i;
    }
    if (i == 0x7f || i + 1 == len) {
        return 0;
    }
    return i + 1;
}

// Trie root hash of RLP-encoded values, the keys are RLP-encoded integers.
// See Section 4.3.2. "Holistic Validity" of the Yellow Paper.
template <class Value, std::invocable<Bytes&, const Value&> Encoder>
evmc::bytes32 root_hash(const std::vector<Value>& v, const Encoder& value_encoder) {
    Bytes index_rlp;
    Bytes value_rlp;

    HashBuilder hb;

    for (size_t j{0}; j < v.size(); ++j) {
        const size_t index{adjust_index_for_rlp(j, v.size())};
        index_rlp.clear();
        rlp::encode(index_rlp, index);
        value_rlp.clear();
        std::invoke(value_encoder, value_rlp, v[index]);

        hb.add_leaf(unpack_nibbles(index_rlp), value_rlp);
    }

    return hb.root_hash();
}

}  // namespace silkworm::trie
