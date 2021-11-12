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

#ifndef SILKWORM_HEADER_ONLY_STATE_HPP
#define SILKWORM_HEADER_ONLY_STATE_HPP

#include <silkworm/state/state.hpp>
#include "chain_elements.hpp"
#include "types.hpp"

namespace silkworm {

class HeaderOnlyChainStateBase : public State {
  public:
    std::optional<BlockHeader> read_header(uint64_t block_number,
                                           const evmc::bytes32& block_hash) const noexcept override =0;

    // methods we don't want to implement
    std::optional<Account> read_account(const evmc::address&) const noexcept override;

    ByteView read_code(const evmc::bytes32& code_hash) const noexcept override;

    evmc::bytes32 read_storage(const evmc::address& address, uint64_t incarnation,
                               const evmc::bytes32& location) const noexcept override;

    uint64_t previous_incarnation(const evmc::address& address) const noexcept override;

    std::optional<BlockBody> read_body(uint64_t block_number, const evmc::bytes32& block_hash) const noexcept override;

    std::optional<intx::uint256> total_difficulty(uint64_t block_number,
                                                  const evmc::bytes32& block_hash) const noexcept override;

    evmc::bytes32 state_root_hash() const override;

    uint64_t current_canonical_block() const override;

    std::optional<evmc::bytes32> canonical_hash(uint64_t block_number) const override;

    void insert_block(const Block& block, const evmc::bytes32& hash) override;

    void canonize_block(uint64_t block_number, const evmc::bytes32& block_hash) override;

    void decanonize_block(uint64_t block_number) override;

    void insert_receipts(uint64_t block_number, const std::vector<Receipt>& receipts) override;

    void begin_block(uint64_t block_number) override;

    void update_account(const evmc::address& address, std::optional<Account> initial,
                        std::optional<Account> current) override;

    void update_account_code(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& code_hash,
                             ByteView code) override;

    void update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location,
                        const evmc::bytes32& initial, const evmc::bytes32& current) override;

    void unwind_state_changes(uint64_t block_number) override;

};

// A Chain_State implementation tied to WorkingChain needs

class HeaderOnlyChainState : public HeaderOnlyChainStateBase {
    OldestFirstLinkQueue& persistedLinkQueue_;  // not nice

  public:
    HeaderOnlyChainState(OldestFirstLinkQueue& persistedLinkQueue);

    std::optional<BlockHeader> read_header(uint64_t block_number,
                                           const evmc::bytes32& block_hash) const noexcept override;
};

// A better Chain_State implementation

class HeaderOnlyChainStateNew : public HeaderOnlyChainStateBase {
    using BlockNumHashPair = std::pair<BlockNum,Hash>;
    std::map<BlockNumHashPair, BlockHeader> headers_;    // (block number, hash) -> header

  public:
    void insert_header(const BlockHeader& header, const evmc::bytes32& hash);

    std::optional<BlockHeader> read_header(uint64_t block_number,
                                           const evmc::bytes32& block_hash) const noexcept override;
};

}  // namespace silkworm

#endif  // SILKWORM_HEADER_ONLY_STATE_HPP
