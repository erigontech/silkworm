/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_TRIE_VECTOR_ROOT_HPP_
#define SILKWORM_TRIE_VECTOR_ROOT_HPP_

#include <silkworm/rlp/encode.hpp>
#include <silkworm/trie/hash_builder.hpp>

namespace silkworm::trie {

// Lexicographic order for RLP-encoded integers is the same as their natural order,
// save for 0, which, due to its RLP encoding, should be placed between 0x7f and 0x80.
inline size_t adjust_index_for_rlp(size_t i, size_t len) {
    if (i > 0x7f) {
        return i;
    } else if (i == 0x7f || i + 1 == len) {
        return 0;
    } else {
        return i + 1;
    }
}

// Trie root hash of RLP-encoded values, the keys are RLP-encoded integers.
// See Section 4.3.2. "Holistic Validity" of the Yellow Paper.
template <class Value, typename Encoder>
evmc::bytes32 root_hash(const std::vector<Value>& v, Encoder value_encoder) {
    Bytes index_rlp;
    Bytes value_rlp;

    HashBuilder hb;

    for (size_t j{0}; j < v.size(); ++j) {
        const size_t index{adjust_index_for_rlp(j, v.size())};
        index_rlp.clear();
        rlp::encode(index_rlp, index);
        value_rlp.clear();
        value_encoder(value_rlp, v[index]);

        hb.add(index_rlp, value_rlp);
    }

    return hb.root_hash();
}

}  // namespace silkworm::trie

#endif  // SILKWORM_TRIE_VECTOR_ROOT_HPP_
