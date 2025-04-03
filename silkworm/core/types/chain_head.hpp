// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>

#include "block_id.hpp"
#include "hash.hpp"

namespace silkworm {

struct ChainHead {
    BlockNum block_num{0};
    Hash hash;
    intx::uint256 total_difficulty;

    friend bool operator==(const ChainHead&, const ChainHead&) = default;
};

inline bool operator==(const ChainHead& a, const BlockId& b) {
    return a.block_num == b.block_num && a.hash == b.hash;
}

inline bool operator==(const BlockId& a, const ChainHead& b) {
    return a.block_num == b.block_num && a.hash == b.hash;
}

inline BlockId to_block_id(const ChainHead& head) {
    return {.block_num = head.block_num, .hash = head.hash};
}

}  // namespace silkworm
