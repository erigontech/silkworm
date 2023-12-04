/*
   Copyright 2023 The Silkworm Authors

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

#include <optional>
#include <string>
#include <vector>

#include <silkworm/core/state/state.hpp>
#include <silkworm/rpc/types/call.hpp>

namespace silkworm::rpc::state {

class OverrideState : public silkworm::State {
  public:
    explicit OverrideState(silkworm::State& inner_state, const AccountsOverrides& accounts_overrides);

    std::optional<silkworm::Account> read_account(const evmc::address& address) const noexcept override;

    silkworm::ByteView read_code(const evmc::bytes32& code_hash) const noexcept override;

    evmc::bytes32 read_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location) const noexcept override;

    uint64_t previous_incarnation(const evmc::address& address) const noexcept override {
        return inner_state_.previous_incarnation(address);
    }

    std::optional<silkworm::BlockHeader> read_header(BlockNum block_number, const evmc::bytes32& block_hash) const noexcept override;

    bool read_body(BlockNum block_number, const evmc::bytes32& block_hash, silkworm::BlockBody& out) const noexcept override;

    std::optional<intx::uint256> total_difficulty(BlockNum block_number, const evmc::bytes32& block_hash) const noexcept override;

    evmc::bytes32 state_root_hash() const override {
        return inner_state_.state_root_hash();
    }

    BlockNum current_canonical_block() const override {
        return inner_state_.current_canonical_block();
    }

    std::optional<evmc::bytes32> canonical_hash(BlockNum block_number) const override;

    void insert_block(const silkworm::Block& block, const evmc::bytes32& hash) override {
        return inner_state_.insert_block(block, hash);
    }

    void canonize_block(BlockNum block_number, const evmc::bytes32& block_hash) override {
        return inner_state_.canonize_block(block_number, block_hash);
    }

    void decanonize_block(BlockNum block_number) override {
        return inner_state_.decanonize_block(block_number);
    }

    void insert_receipts(BlockNum block_number, const std::vector<silkworm::Receipt>& receipts) override {
        return inner_state_.insert_receipts(block_number, receipts);
    }

    void insert_call_traces(BlockNum block_number, const CallTraces& traces) override {
        return inner_state_.insert_call_traces(block_number, traces);
    }

    void begin_block(BlockNum block_number) override {
        return inner_state_.begin_block(block_number);
    }

    void update_account(
        const evmc::address& address,
        std::optional<silkworm::Account> initial,
        std::optional<silkworm::Account> current) override {
        return inner_state_.update_account(address, initial, current);
    }

    void update_account_code(
        const evmc::address& address,
        uint64_t incarnation,
        const evmc::bytes32& code_hash,
        silkworm::ByteView code) override {
        return inner_state_.update_account_code(address, incarnation, code_hash, code);
    }

    void update_storage(
        const evmc::address& address,
        uint64_t incarnation,
        const evmc::bytes32& location,
        const evmc::bytes32& initial,
        const evmc::bytes32& current) override {
        return inner_state_.update_storage(address, incarnation, location, initial, current);
    }

    void unwind_state_changes(BlockNum block_number) override {
        return inner_state_.unwind_state_changes(block_number);
    }

  private:
    silkworm::State& inner_state_;
    const AccountsOverrides& accounts_overrides_;
    std::map<evmc::bytes32, silkworm::ByteView> code_hash_;
};

}  // namespace silkworm::rpc::state
