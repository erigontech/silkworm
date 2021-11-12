/*
Copyright 2020-2021 The Silkworm Authors

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

HeaderOnlyChainState::HeaderOnlyChainState(OldestFirstLinkQueue& persistedLinkQueue)
    : persistedLinkQueue_(persistedLinkQueue) {}

std::optional<BlockHeader> HeaderOnlyChainState::read_header(BlockNum block_number,
                                                             const evmc::bytes32& hash) const noexcept {
    // todo: very slow implementation, improve it!

    for(auto& link: persistedLinkQueue_) {
        if (link->blockHeight == block_number && hash == link->hash) {
            return *link->header;
        }
    }

    return std::nullopt;
}

// A better Chain_State implementation

void HeaderOnlyChainStateNew::insert_header(const BlockHeader& header, const evmc::bytes32& hash) {
    headers_[{header.number, hash}] = header;
}

std::optional<BlockHeader> HeaderOnlyChainStateNew::read_header(BlockNum block_number,
                                                                const evmc::bytes32& hash) const noexcept {
    auto item = headers_.find({block_number, hash});

    if (item == headers_.end()) {
        return std::nullopt;
    }

    return item->second;
}

// methods we don't want to implement

std::optional<Account> HeaderOnlyChainStateBase::read_account(const evmc::address&) const noexcept {
    assert(false);  // not implemented
}

ByteView HeaderOnlyChainStateBase::read_code(const evmc::bytes32&) const noexcept {
    assert(false);  // not implemented
}

evmc::bytes32 HeaderOnlyChainStateBase::read_storage(const evmc::address&, uint64_t,
                                                     const evmc::bytes32&) const noexcept {
    assert(false);  // not implemented
}

uint64_t HeaderOnlyChainStateBase::previous_incarnation(const evmc::address&) const noexcept {
    assert(false);  // not implemented
}

std::optional<BlockBody> HeaderOnlyChainStateBase::read_body(uint64_t, const evmc::bytes32&) const noexcept {
    assert(false);  // not implemented
}

std::optional<intx::uint256> HeaderOnlyChainStateBase::total_difficulty(uint64_t, const evmc::bytes32&) const noexcept {
    assert(false);  // not implemented
}

evmc::bytes32 HeaderOnlyChainStateBase::state_root_hash() const {
    assert(false);  // not implemented
}

uint64_t HeaderOnlyChainStateBase::current_canonical_block() const {
    assert(false);  // not implemented
}

std::optional<evmc::bytes32> HeaderOnlyChainStateBase::canonical_hash(uint64_t) const {
    assert(false);  // not implemented
}

void HeaderOnlyChainStateBase::insert_block(const Block&, const evmc::bytes32&) {
    assert(false);  // not implemented
}

void HeaderOnlyChainStateBase::canonize_block(uint64_t, const evmc::bytes32&) {
    assert(false);  // not implemented
}

void HeaderOnlyChainStateBase::decanonize_block(uint64_t) {
    assert(false);  // not implemented
}

void HeaderOnlyChainStateBase::insert_receipts(uint64_t, const std::vector<Receipt>&) {
    assert(false);  // not implemented
}

void HeaderOnlyChainStateBase::begin_block(uint64_t) {
    assert(false);  // not implemented
}

void HeaderOnlyChainStateBase::update_account(const evmc::address&, std::optional<Account>, std::optional<Account>) {
    assert(false);  // not implemented
}

void HeaderOnlyChainStateBase::update_account_code(const evmc::address&, uint64_t, const evmc::bytes32&, ByteView) {
    assert(false);  // not implemented
}

void HeaderOnlyChainStateBase::update_storage(const evmc::address&, uint64_t, const evmc::bytes32&,
                                              const evmc::bytes32&, const evmc::bytes32&) {
    assert(false);  // not implemented
}

void HeaderOnlyChainStateBase::unwind_state_changes(uint64_t) {
    assert(false);  // not implemented
}

}  // namespace silkworm