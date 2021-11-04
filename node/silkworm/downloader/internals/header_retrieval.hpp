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

#ifndef SILKWORM_HEADER_RETRIEVAL_HPP
#define SILKWORM_HEADER_RETRIEVAL_HPP

#include "db_tx.hpp"
#include "types.hpp"

namespace silkworm {

/*
 * HeaderRetrieval has the responsibility to retrieve BlockHeader from the db using the hash or the block number.
 */
class HeaderRetrieval {
  public:
    static const long soft_response_limit = 2 * 1024 * 1024;  // Target maximum size of returned blocks
    static const long est_header_rlp_size = 500;              // Approximate size of an RLP encoded block header
    static const long max_headers_serve = 1024;  // Amount of block headers to be fetched per retrieval request

    explicit HeaderRetrieval(Db::ReadOnlyAccess db_access);

    // Headers
    std::vector<BlockHeader> recover_by_hash(Hash origin, uint64_t amount, uint64_t skip, bool reverse);
    std::vector<BlockHeader> recover_by_number(BlockNum origin, uint64_t amount, uint64_t skip, bool reverse);

    // Node current status
    BlockNum head_height();
    std::tuple<Hash, BigInt> head_hash_and_total_difficulty();

    // Ancestor
    std::tuple<Hash, BlockNum> get_ancestor(Hash hash, BlockNum blockNum, BlockNum ancestorDelta,
                                            uint64_t& max_non_canonical);

  protected:
    Db::ReadOnlyAccess::Tx db_tx_;
};

}  // namespace silkworm

#endif  // SILKWORM_HEADER_RETRIEVAL_HPP
