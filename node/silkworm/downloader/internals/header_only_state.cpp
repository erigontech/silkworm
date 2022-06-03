/*
Copyright 2020-2022 The Silkworm Authors

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

#include "header_only_state.hpp"

namespace silkworm {

// A Chain_State implementation tied to WorkingChain needs

CustomHeaderOnlyChainState::CustomHeaderOnlyChainState(OldestFirstLinkMap& persistedLinkQueue)
    : persistedLinkQueue_(persistedLinkQueue) {}

std::optional<BlockHeader> CustomHeaderOnlyChainState::read_header(BlockNum block_number,
                                                                   const evmc::bytes32& hash) const noexcept {
    auto [initial_link, final_link] = persistedLinkQueue_.equal_range(block_number);

    for (auto link = initial_link; link != final_link; link++) {
        if (link->second->blockHeight == block_number && link->second->hash == hash) {
            return *link->second->header;
        }
    }

    return std::nullopt;
}

bool CustomHeaderOnlyChainState::read_body(BlockNum, const evmc::bytes32&, BlockBody&) const noexcept {
    assert(false);  // not implemented
    return false;
}

std::optional<intx::uint256> CustomHeaderOnlyChainState::total_difficulty(uint64_t,
                                                                          const evmc::bytes32&) const noexcept {
    assert(false);  // not implemented
    return {};
}

// A better Chain_State implementation

void SimpleHeaderOnlyChainState::insert_header(const BlockHeader& header, const evmc::bytes32& hash) {
    headers_[{header.number, hash}] = header;
}

std::optional<BlockHeader> SimpleHeaderOnlyChainState::read_header(BlockNum block_number,
                                                                   const evmc::bytes32& hash) const noexcept {
    auto item = headers_.find({block_number, hash});

    if (item == headers_.end()) {
        return std::nullopt;
    }

    return item->second;
}

bool SimpleHeaderOnlyChainState::read_body(BlockNum, const evmc::bytes32&, BlockBody&) const noexcept {
    assert(false);  // not implemented
    return false;
}

std::optional<intx::uint256> SimpleHeaderOnlyChainState::total_difficulty(uint64_t,
                                                                          const evmc::bytes32&) const noexcept {
    assert(false);  // not implemented
    return {};
}

}  // namespace silkworm
