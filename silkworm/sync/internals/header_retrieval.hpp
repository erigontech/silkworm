// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/access_layer.hpp>

#include "types.hpp"

namespace silkworm {

/*
 * HeaderRetrieval has the responsibility to retrieve BlockHeader from the db using the hash or the block number.
 */
class HeaderRetrieval {
  public:
    static const int kSoftResponseLimit = 2 * 1024 * 1024;  // Target maximum size of returned blocks
    static const int kEstHeaderRlpSize = 500;               // Approximate size of an RLP encoded block header
    static const int kMaxHeadersServe = 1024;               // Amount of block headers to be fetched per retrieval request

    explicit HeaderRetrieval(db::DataModel data_model)
        : data_model_{data_model} {}

    // Headers
    std::vector<BlockHeader> recover_by_hash(Hash origin, uint64_t amount, uint64_t skip, bool reverse);
    std::vector<BlockHeader> recover_by_number(BlockNum origin, uint64_t amount, uint64_t skip, bool reverse);

    // Ancestor
    std::tuple<Hash, BlockNum> get_ancestor(Hash hash, BlockNum block_num, BlockNum ancestor_delta,
                                            uint64_t& max_non_canonical);

  protected:
    db::DataModel data_model_;
};

}  // namespace silkworm
