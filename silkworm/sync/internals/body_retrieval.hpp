// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/access_layer.hpp>

#include "types.hpp"

namespace silkworm {

class BodyRetrieval {
  public:
    static const int kSoftResponseLimit = 2 * 1024 * 1024;  // Target maximum size of returned blocks
    static const int kMaxBodiesServe = 1024;                // Amount of block bodies to be fetched per retrieval request

    explicit BodyRetrieval(db::ROTxn& db_tx)
        : db_tx_{db_tx} {}

    std::vector<BlockBody> recover(std::vector<Hash>);

  protected:
    db::ROTxn& db_tx_;
};

}  // namespace silkworm
