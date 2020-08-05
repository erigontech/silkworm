/*
   Copyright 2020 The Silkworm Authors

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

#ifndef SILKWORM_TRIE_HASH_BUILDER_H_
#define SILKWORM_TRIE_HASH_BUILDER_H_

#include <array>
#include <silkworm/common/base.hpp>

namespace silkworm::trie {

// Calculates root hash of a Modified Merkle Patricia Trie.
// See Appendix D "Modified Merkle Patricia Trie" of the Yellow Paper
// and https://eth.wiki/fundamentals/patricia-tree
class HashBuilder {
 public:
  HashBuilder(const HashBuilder&) = delete;
  HashBuilder& operator=(const HashBuilder&) = delete;

  // Must be constructed with the very first (lexicographically) key/value pair.
  HashBuilder(ByteView key0, ByteView val0);

  // Entries must be added in the strictly increasing lexicographic order (by key).
  // Consequently, duplicate keys are not allowed.
  void add(ByteView key, ByteView val);

  evmc::bytes32 root_hash();

 private:
  Bytes branch_node_rlp() const;

  Bytes path_;
  uint16_t branch_mask_{0};
  std::array<Bytes, 16> children_;
  Bytes value_;
};
}  // namespace silkworm::trie

#endif  // SILKWORM_TRIE_HASH_BUILDER_H_
