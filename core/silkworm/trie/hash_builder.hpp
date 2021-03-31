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

#ifndef SILKWORM_TRIE_HASH_BUILDER_HPP_
#define SILKWORM_TRIE_HASH_BUILDER_HPP_

#include <vector>

#include <silkworm/common/base.hpp>

namespace silkworm::trie {

// TG DecompressNibbles
Bytes unpack_nibbles(ByteView packed);

// Calculates root hash of a Modified Merkle Patricia Trie.
// See Appendix D "Modified Merkle Patricia Trie" of the Yellow Paper
// and https://eth.wiki/fundamentals/patricia-tree
class HashBuilder {
  public:
    HashBuilder(const HashBuilder&) = delete;
    HashBuilder& operator=(const HashBuilder&) = delete;

    HashBuilder() = default;

    // Entries must be added in the strictly increasing lexicographic order (by key).
    // Consequently, duplicate keys are not allowed.
    // In addition, a key may not be a prefix of another key
    // (e.g. keys "ab" & "ab05" are mutually exclusive).
    void add(ByteView key, ByteView value);

    // May only be called after all entries have been added.
    evmc::bytes32 root_hash();

  private:
    void gen_struct_step(ByteView curr, ByteView succ, ByteView value);

    void branch_ref(uint16_t mask);

    Bytes key_;  // unpacked – one nibble per byte
    Bytes value_;

    std::vector<uint16_t> groups_;
    std::vector<Bytes> stack_;  // node references: hashes or embedded RLPs
};

}  // namespace silkworm::trie

#endif  // SILKWORM_TRIE_HASH_BUILDER_HPP_
