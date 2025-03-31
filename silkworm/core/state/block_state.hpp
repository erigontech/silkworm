// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>

namespace silkworm {

class BlockState {
  public:
    virtual ~BlockState() = default;

    virtual std::optional<BlockHeader> read_header(
        BlockNum block_num,
        const evmc::bytes32& block_hash) const noexcept = 0;

    // Returns true on success and false on missing block
    [[nodiscard]] virtual bool read_body(
        BlockNum block_num,
        const evmc::bytes32& block_hash,
        BlockBody& out) const noexcept = 0;

    virtual std::optional<intx::uint256> total_difficulty(
        uint64_t block_num,
        const evmc::bytes32& block_hash) const noexcept = 0;
};

}  // namespace silkworm
