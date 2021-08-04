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

#ifndef SILKWORM_HEADERLOGIC_HPP
#define SILKWORM_HEADERLOGIC_HPP

#include "Types.hpp"
#include "DbTx.hpp"
#include <vector>
#include <queue>
#include <map>

namespace silkworm {

class HeaderLogic {     // todo: modularize this!
  public:
    static const long soft_response_limit = 2 * 1024 * 1024; // Target maximum size of returned blocks, headers or node data.
    static const long est_header_rlp_size = 500;             // Approximate size of an RLP encoded block header
    static const long max_headers_serve = 1024;              // Amount of block headers to be fetched per retrieval request

    // Headers
    static std::vector<BlockHeader> recoverByHash(Hash origin, uint64_t amount, uint64_t skip, bool reverse);
    static std::vector<BlockHeader> recoverByNumber(BlockNum origin, uint64_t amount, uint64_t skip, bool reverse);

    // Node current status
    static BlockNum                head_height(DbTx& db);
    static std::tuple<Hash,BigInt> head_hash_and_total_difficulty(DbTx& db);

    // Ancestor
    static std::tuple<Hash,BlockNum> getAncestor(DbTx& db, Hash hash, BlockNum blockNum, BlockNum ancestor, uint64_t& max_non_canonical);
};

}

#endif  // SILKWORM_HEADERLOGIC_HPP
