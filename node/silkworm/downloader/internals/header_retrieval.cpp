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

#include <silkworm/common/log.hpp>

#include "header_retrieval.hpp"
#include "silkworm/downloader/block_provider.hpp"

namespace silkworm {

HeaderRetrieval::HeaderRetrieval(DbTx& db): db_(db) {

}

std::vector<BlockHeader> HeaderRetrieval::recover_by_hash(Hash origin, uint64_t amount, uint64_t skip, bool reverse) {
    using std::optional;
    uint64_t max_non_canonical = 100;

    std::vector<BlockHeader> headers;
    long long bytes = 0;
    Hash hash = origin;
    bool unknown = false;

    // first
    optional<BlockHeader> header = db_.read_header(hash);
    if (!header) return headers;
    BlockNum block_num = header->number;
    headers.push_back(*header);
    bytes += est_header_rlp_size;

    // followings
    do {
        // compute next hash & number - todo: understand
        if (!reverse) {
            BlockNum current = header->number;
            BlockNum next = current + skip + 1;
            if (next <= current) {
                unknown = true;
                SILKWORM_LOG(LogLevel::Warn)
                    << "GetBlockHeaders skip overflow attack:"
                    << " current=" << current
                    << ", skip=" << skip
                    << ", next=" << next << std::endl;
            }
            else {
                header = db_.read_canonical_header(next);
                if (!header)
                    unknown = true;
                else {
                    Hash nextHash = header->hash();
                    auto [expOldHash, _ ] = get_ancestor(nextHash, next, skip + 1, max_non_canonical);
                    if (expOldHash == hash) {
                        hash = nextHash;
                        block_num = next;
                    }
                    else
                        unknown = true;
                }
            }
        }
        else {  // reverse
            BlockNum ancestor = skip + 1;
            if (ancestor == 0)
                unknown = true;
            else
                std::tie(hash, block_num) = get_ancestor(hash, block_num, ancestor, max_non_canonical);
        }

        // end todo: understand

        if (unknown) break;

        header = db_.read_header(block_num, hash);
        if (!header) break;
        headers.push_back(*header);
        bytes += est_header_rlp_size;

    } while(headers.size() < amount && bytes < soft_response_limit && headers.size() < max_headers_serve);

    return headers;
}

std::vector<BlockHeader> HeaderRetrieval::recover_by_number(BlockNum origin, uint64_t amount, uint64_t skip, bool reverse) {
    using std::optional;

    std::vector<BlockHeader> headers;
    long long bytes = 0;
    BlockNum block_num = origin;

    do {
        optional<BlockHeader> header = db_.read_canonical_header(block_num);
        if (!header) break;

        headers.push_back(*header);
        bytes += est_header_rlp_size;

        if (!reverse)
            block_num += skip + 1; // Number based traversal towards the leaf block
        else
            block_num -= skip + 1; // Number based traversal towards the genesis block

    } while(block_num > 0 && headers.size() < amount && bytes < soft_response_limit && headers.size() < max_headers_serve);

    return headers;
}

// Node current status
BlockNum HeaderRetrieval::head_height() {
    return db_.stage_progress(db::stages::kBlockBodiesKey);
}

std::tuple<Hash,BigInt> HeaderRetrieval::head_hash_and_total_difficulty() {
    BlockNum head_height = db_.stage_progress(db::stages::kBlockBodiesKey);
    auto head_hash = db_.read_canonical_hash(head_height);
    if (!head_hash)
        throw std::logic_error("canonical hash at height " + std::to_string(head_height) + " not found in db");
    std::optional<BigInt> head_td = db_.read_total_difficulty(head_height, *head_hash);
    if (!head_td)
        throw std::logic_error("total difficulty of canonical hash at height " + std::to_string(head_height) +
                               " not found in db");
    return {*head_hash, *head_td};
}

std::tuple<Hash,BlockNum> HeaderRetrieval::get_ancestor(Hash hash, BlockNum blockNum, BlockNum ancestor, uint64_t& max_non_canonical) {
    if (ancestor > blockNum)
        return {Hash{},0};

    if (ancestor == 1) {
        auto header = db_.read_header(blockNum, hash);
        if (header)
            return {header->parent_hash, blockNum-1};
        else
            return {Hash{},0};
    }

    while (ancestor != 0) {
        auto h = db_.read_canonical_hash(blockNum);
        if (h == hash) {
            auto ancestorHash = db_.read_canonical_hash(blockNum - ancestor);
            h = db_.read_canonical_hash(blockNum);
            if (h == hash) {
                blockNum -= ancestor;
                return {*ancestorHash, blockNum};   // ancestorHash can be empty
            }
        }
        if (max_non_canonical == 0)
            return {Hash{},0};
        max_non_canonical--;
        ancestor--;
        auto header = db_.read_header(blockNum, hash);
        if (!header)
            return {Hash{},0};
        hash = header->parent_hash;
        blockNum--;
    }
    return {hash, blockNum};
}

}
