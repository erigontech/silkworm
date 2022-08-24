/*
   Copyright 2022 The Silkworm Authors

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
#include <silkworm/db/stages.hpp>

namespace silkworm {

HeaderRetrieval::HeaderRetrieval(db::ROAccess db_access) : db_tx_{db_access.start_ro_tx()} {}

std::vector<BlockHeader> HeaderRetrieval::recover_by_hash(Hash origin, uint64_t amount, uint64_t skip, bool reverse) {
    using std::optional;
    uint64_t max_non_canonical = 100;

    std::vector<BlockHeader> headers;
    long long bytes = 0;
    Hash hash = origin;
    bool unknown = false;

    // first
    optional<BlockHeader> header = read_header(db_tx_, hash.bytes);
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
                header = db::read_canonical_header(db_tx_, next);
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

        header = read_header(db_tx_, block_num, hash);
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
        optional<BlockHeader> header = db::read_canonical_header(db_tx_, block_num);
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
BlockNum HeaderRetrieval::head_height() { return db::stages::read_stage_progress(db_tx_, db::stages::kBlockBodiesKey); }

std::tuple<Hash, BigInt> HeaderRetrieval::head_hash_and_total_difficulty() {
    BlockNum head_height = db::stages::read_stage_progress(db_tx_, db::stages::kBlockBodiesKey);
    auto head_hash = db::read_canonical_hash(db_tx_, head_height);
    if (!head_hash)
        throw std::logic_error("canonical hash at height " + std::to_string(head_height) + " not found in db");
    std::optional<BigInt> head_td = db::read_total_difficulty(db_tx_, head_height, *head_hash);
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
        auto header = db::read_header(db_tx_, blockNum, hash);
        if (header) {
            return {header->parent_hash, blockNum - 1};
        } else {
            return {Hash{}, 0};
        }
    }

    while (ancestorDelta != 0) {
        auto h = read_canonical_hash(db_tx_, blockNum);
        if (h == hash) {
            auto ancestorHash = db::read_canonical_hash(db_tx_, blockNum - ancestorDelta);
            // todo: blockNum - ancestorDelta = constant, it is correct?
            h = db::read_canonical_hash(db_tx_, blockNum);         // todo: dummy line, remove (also present in Erigon)
            if (h == hash) {                                       // todo: dummy line, remove
                return {*ancestorHash, blockNum - ancestorDelta};  // ancestorHash can be empty
            }
        }
        if (max_non_canonical == 0) return {Hash{}, 0};
        max_non_canonical--;
        ancestorDelta--;
        auto header = db::read_header(db_tx_, blockNum, hash);
        if (!header) return {Hash{}, 0};
        hash = header->parent_hash;
        blockNum--;
    }
    return {hash, blockNum};
}

}  // namespace silkworm
