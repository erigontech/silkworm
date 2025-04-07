// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/state/block_state.hpp>

#include "chain_elements.hpp"
#include "types.hpp"

namespace silkworm {

// A Chain_State implementation tied to WorkingChain needs

class CustomHeaderOnlyChainState : public BlockState {
    OldestFirstLinkMap& persisted_link_queue_;  // not nice

  public:
    explicit CustomHeaderOnlyChainState(OldestFirstLinkMap& persisted_link_queue);

    std::optional<BlockHeader> read_header(
        uint64_t block_num,
        const evmc::bytes32& block_hash) const noexcept override;

    [[nodiscard]] bool read_body(
        BlockNum block_num,
        const evmc::bytes32& block_hash,
        BlockBody& out) const noexcept override;

    std::optional<intx::uint256> total_difficulty(
        uint64_t block_num,
        const evmc::bytes32& block_hash) const noexcept override;
};

// A better Chain_State implementation

class SimpleHeaderOnlyChainState : public BlockState {
    using BlockNumHashPair = std::pair<BlockNum, Hash>;
    std::map<BlockNumHashPair, BlockHeader> headers_;  // (block number, hash) -> header

  public:
    void insert_header(const BlockHeader& header, const evmc::bytes32& hash);

    std::optional<BlockHeader> read_header(
        uint64_t block_num,
        const evmc::bytes32& block_hash) const noexcept override;

    [[nodiscard]] bool read_body(
        BlockNum block_num,
        const evmc::bytes32& block_hash,
        BlockBody& out) const noexcept override;

    std::optional<intx::uint256> total_difficulty(
        uint64_t block_num,
        const evmc::bytes32& block_hash) const noexcept override;
};

}  // namespace silkworm
