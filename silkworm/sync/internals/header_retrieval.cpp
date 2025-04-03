// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "header_retrieval.hpp"

#include <cstdint>

#include <silkworm/infra/common/log.hpp>

namespace silkworm {

std::vector<BlockHeader> HeaderRetrieval::recover_by_hash(Hash origin, uint64_t amount, uint64_t skip, bool reverse) {
    using std::optional;
    uint64_t max_non_canonical = 100;

    std::vector<BlockHeader> headers;
    int64_t bytes = 0;
    Hash hash = origin;
    bool unknown = false;

    // first
    optional<BlockHeader> header = data_model_.read_header(hash);
    if (!header) return headers;
    BlockNum block_num = header->number;
    headers.push_back(*header);
    bytes += kEstHeaderRlpSize;

    // followings
    do {
        // compute next hash & number - understand and improve readability
        if (!reverse) {
            BlockNum current = header->number;
            BlockNum next = current + skip + 1;
            if (next <= current) {  // true only if there is an overflow
                unknown = true;
                SILK_WARN_M("chainsync::HeaderRetrieval")
                    << "GetBlockHeaders skip overflow attack:"
                    << " current=" << current
                    << ", skip=" << skip
                    << ", next=" << next;
            } else {
                header = data_model_.read_canonical_header(next);
                if (!header) {
                    unknown = true;
                } else {
                    Hash next_hash = header->hash();
                    auto [exp_next_hash, _] = get_ancestor(next_hash, next, skip + 1, max_non_canonical);
                    if (exp_next_hash == hash) {
                        hash = next_hash;
                        block_num = next;
                    } else {
                        unknown = true;
                    }
                }
            }
        } else {  // reverse
            BlockNum ancestor_delta = skip + 1;
            if (ancestor_delta == 0)
                unknown = true;
            else
                std::tie(hash, block_num) = get_ancestor(hash, block_num, ancestor_delta, max_non_canonical);
        }

        // end understand

        if (unknown) break;

        header = data_model_.read_header(block_num, hash);
        if (!header) break;
        headers.push_back(*header);
        bytes += kEstHeaderRlpSize;

    } while (headers.size() < amount && bytes < kSoftResponseLimit && headers.size() < kMaxHeadersServe);

    return headers;
}

std::vector<BlockHeader> HeaderRetrieval::recover_by_number(BlockNum origin, uint64_t amount, uint64_t skip,
                                                            bool reverse) {
    using std::optional;

    std::vector<BlockHeader> headers;
    int64_t bytes = 0;
    BlockNum block_num = origin;

    do {
        optional<BlockHeader> header = data_model_.read_canonical_header(block_num);
        if (!header) break;

        headers.push_back(*header);
        bytes += kEstHeaderRlpSize;

        if (!reverse)
            block_num += skip + 1;  // Number based traversal towards the leaf block
        else
            block_num -= skip + 1;  // Number based traversal towards the genesis block

    } while (block_num > 0 && headers.size() < amount && bytes < kSoftResponseLimit &&
             headers.size() < kMaxHeadersServe);

    return headers;
}

std::tuple<Hash, BlockNum> HeaderRetrieval::get_ancestor(Hash hash, BlockNum block_num, BlockNum ancestor_delta,
                                                         uint64_t& max_non_canonical) {
    if (ancestor_delta > block_num) {
        return {Hash{}, 0};
    }

    if (ancestor_delta == 1) {
        auto header = data_model_.read_header(block_num, hash);
        if (header) {
            return {header->parent_hash, block_num - 1};
        }
        return {Hash{}, 0};
    }

    while (ancestor_delta != 0) {
        auto h = data_model_.read_canonical_header_hash(block_num);
        if (h == hash) {
            auto ancestor_hash = data_model_.read_canonical_header_hash(block_num - ancestor_delta);
            if (!ancestor_hash) {
                return {Hash{}, 0};
            }
            return {*ancestor_hash, block_num - ancestor_delta};
        }
        if (max_non_canonical == 0) {
            return {Hash{}, 0};
        }
        --max_non_canonical;
        --ancestor_delta;
        auto header = data_model_.read_header(block_num, hash);
        if (!header) {
            return {Hash{}, 0};
        }
        hash = header->parent_hash;
        --block_num;
    }
    return {hash, block_num};
}

}  // namespace silkworm
