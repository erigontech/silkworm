// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>

#include <silkworm/db/datastore/snapshots/segment/segment_reader.hpp>

namespace silkworm::snapshots {

class BodyTxsAmountSegmentQuery {
  public:
    struct Result {
        uint64_t first_tx_id{};
        uint64_t count{};
    };

    explicit BodyTxsAmountSegmentQuery(const segment::SegmentFileReader& segment) : segment_(segment) {}

    Result exec();

  private:
    const segment::SegmentFileReader& segment_;
};

}  // namespace silkworm::snapshots
