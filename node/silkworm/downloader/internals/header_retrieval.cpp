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

#include "header_retrieval.hpp"

#include <silkworm/common/log.hpp>

namespace silkworm {

HeaderRetrieval::HeaderRetrieval(Db::ReadOnlyAccess db_access) : db_tx_{db_access.start_ro_tx()} {}

std::vector<BlockHeader> HeaderRetrieval::recover_by_hash(Hash origin, uint64_t amount, uint64_t skip, bool reverse) {
    using std::optional;
    uint64_t max_non_canonical = 100;

    std::vector<BlockHeader> headers;
    long long bytes = 0;
    Hash hash = origin;
    bool unknown = false;

    // first
    optional<BlockHeader> header = db_tx_.read_header(hash);
    if (!header) return headers;
    BlockNum block_num = header->number;
    headers.push_back(*header);
    bytes += est_header_rlp_size;

    // followings
    do {
        // compute next hash & number - todo: understand and improve readability
        if (!reverse) {
            BlockNum current = header->number;
            BlockNum next = current + skip + 1;
            if (next <= current) {  // true only if there is an overflow
                unknown = true;
                log::Warning() << "GetBlockHeaders skip overflow attack:"
                                      << " current=" << current << ", skip=" << skip << ", next=" << next;
            } else {
                header = db_tx_.read_canonical_header(next);
                if (!header)
                    unknown = true;
                else {
                    Hash nextHash = header->hash();
                    auto [expOldHash, _] = get_ancestor(nextHash, next, skip + 1, max_non_canonical);
                    if (expOldHash == hash) {
                        hash = nextHash;
                        block_num = next;
                    } else
                        unknown = true;
                }
            }
        } else {  // reverse
            BlockNum ancestor = skip + 1;
            if (ancestor == 0)
                unknown = true;
            else
                std::tie(hash, block_num) = get_ancestor(hash, block_num, ancestor, max_non_canonical);
        }

        // end todo: understand

        if (unknown) break;

        header = db_tx_.read_header(block_num, hash);
        if (!header) break;
        headers.push_back(*header);
        bytes += est_header_rlp_size;

    } while (headers.size() < amount && bytes < soft_response_limit && headers.size() < max_headers_serve);

    return headers;
}

std::vector<BlockHeader> HeaderRetrieval::recover_by_number(BlockNum origin, uint64_t amount, uint64_t skip,
                                                            bool reverse) {
    using std::optional;

    std::vector<BlockHeader> headers;
    long long bytes = 0;
    BlockNum block_num = origin;

    do {
        optional<BlockHeader> header = db_tx_.read_canonical_header(block_num);
        if (!header) break;

        headers.push_back(*header);
        bytes += est_header_rlp_size;

        if (!reverse)
            block_num += skip + 1;  // Number based traversal towards the leaf block
        else
            block_num -= skip + 1;  // Number based traversal towards the genesis block

    } while (block_num > 0 && headers.size() < amount && bytes < soft_response_limit &&
             headers.size() < max_headers_serve);

    return headers;
}

// Node current status
BlockNum HeaderRetrieval::head_height() { return db_tx_.read_stage_progress(db::stages::kBlockBodiesKey); }

std::tuple<Hash, BigInt> HeaderRetrieval::head_hash_and_total_difficulty() {
    BlockNum head_height = db_tx_.read_stage_progress(db::stages::kBlockBodiesKey);
    auto head_hash = db_tx_.read_canonical_hash(head_height);
    if (!head_hash)
        throw std::logic_error("canonical hash at height " + std::to_string(head_height) + " not found in db");
    std::optional<BigInt> head_td = db_tx_.read_total_difficulty(head_height, *head_hash);
    if (!head_td)
        throw std::logic_error("total difficulty of canonical hash at height " + std::to_string(head_height) +
                               " not found in db");
    return {*head_hash, *head_td};
}

// todo: use optional<> here
std::tuple<Hash, BlockNum> HeaderRetrieval::get_ancestor(Hash hash, BlockNum blockNum, BlockNum ancestorDelta,
                                                         uint64_t& max_non_canonical) {
    if (ancestorDelta > blockNum) return {Hash{}, 0};

    if (ancestorDelta == 1) {
        auto header = db_tx_.read_header(blockNum, hash);
        if (header)
            return {header->parent_hash, blockNum - 1};
        else
            return {Hash{}, 0};
    }

    while (ancestorDelta != 0) {
        auto h = db_tx_.read_canonical_hash(blockNum);
        if (h == hash) {
            auto ancestorHash = db_tx_.read_canonical_hash(blockNum - ancestorDelta);
            // todo: blockNum - ancestorDelta = constant, it is correct?
            h = db_tx_.read_canonical_hash(blockNum);              // todo: dummy line, remove (also present in Erigon)
            if (h == hash) {                                       // todo: dummy line, remove
                return {*ancestorHash, blockNum - ancestorDelta};  // ancestorHash can be empty
            }
        }
        if (max_non_canonical == 0) return {Hash{}, 0};
        max_non_canonical--;
        ancestorDelta--;
        auto header = db_tx_.read_header(blockNum, hash);
        if (!header) return {Hash{}, 0};
        hash = header->parent_hash;
        blockNum--;
    }
    return {hash, blockNum};
}

}  // namespace silkworm
