// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "body_retrieval.hpp"

#include <silkworm/core/types/block.hpp>

namespace silkworm {

std::vector<BlockBody> BodyRetrieval::recover(std::vector<Hash> request) {
    std::vector<BlockBody> response;
    size_t bytes = 0;
    for (size_t i = 0; i < request.size(); ++i) {
        Hash& hash = request[i];
        BlockBody body;
        if (!db::read_body(db_tx_, hash, body)) {
            continue;
        }
        response.push_back(body);
        bytes += rlp::length(body);
        if (bytes >= kSoftResponseLimit || response.size() >= kMaxBodiesServe || i >= 2 * kMaxBodiesServe) {
            break;
        }
    }
    return response;
}

}  // namespace silkworm
