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

#ifndef SILKWORM_TRIE_DB_TRIE_HPP_
#define SILKWORM_TRIE_DB_TRIE_HPP_

#include <vector>

#include <silkworm/common/base.hpp>
#include <silkworm/db/chaindb.hpp>

namespace silkworm::trie {

struct Node {
    uint16_t state_mask{0};
    uint16_t tree_mask{0};
    uint16_t hash_mask{0};

    std::vector<evmc::bytes32> hashes{};
};

// TG UnmarshalTrieNode
Node unmarshal_node(ByteView v);

// TG RegenerateIntermediateHashes
// returns root hash
evmc::bytes32 regenerate_db_tries(lmdb::Transaction& txn);

}  // namespace silkworm::trie

#endif  // SILKWORM_TRIE_DB_TRIE_HPP_
