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
