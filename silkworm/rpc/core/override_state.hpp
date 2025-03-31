// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <vector>

#include <silkworm/core/state/state.hpp>
#include <silkworm/rpc/types/call.hpp>

namespace silkworm::rpc::state {

class OverrideState : public silkworm::State {
  public:
    explicit OverrideState(silkworm::State& inner_state, const AccountsOverrides& accounts_overrides);

    std::optional<silkworm::Account> read_account(const evmc::address& address) const noexcept override;

    silkworm::ByteView read_code(const evmc::address& address, const evmc::bytes32& code_hash) const noexcept override;

    evmc::bytes32 read_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location) const noexcept override;

    uint64_t previous_incarnation(const evmc::address& address) const noexcept override {
        return inner_state_.previous_incarnation(address);
    }

    std::optional<silkworm::BlockHeader> read_header(BlockNum block_num, const evmc::bytes32& block_hash) const noexcept override;

    bool read_body(BlockNum block_num, const evmc::bytes32& block_hash, silkworm::BlockBody& out) const noexcept override;

    std::optional<intx::uint256> total_difficulty(BlockNum block_num, const evmc::bytes32& block_hash) const noexcept override;

    evmc::bytes32 state_root_hash() const override {
        return inner_state_.state_root_hash();
    }

    BlockNum current_canonical_block() const override {
        return inner_state_.current_canonical_block();
    }

    std::optional<evmc::bytes32> canonical_hash(BlockNum block_num) const override;

    void insert_block(const silkworm::Block& block, const evmc::bytes32& hash) override {
        inner_state_.insert_block(block, hash);
    }

    void canonize_block(BlockNum block_num, const evmc::bytes32& block_hash) override {
        inner_state_.canonize_block(block_num, block_hash);
    }

    void decanonize_block(BlockNum block_num) override {
        inner_state_.decanonize_block(block_num);
    }

    void insert_receipts(BlockNum block_num, const std::vector<silkworm::Receipt>& receipts) override {
        inner_state_.insert_receipts(block_num, receipts);
    }

    void insert_call_traces(BlockNum block_num, const CallTraces& traces) override {
        inner_state_.insert_call_traces(block_num, traces);
    }

    void begin_block(BlockNum block_num, size_t updated_accounts_count) override {
        inner_state_.begin_block(block_num, updated_accounts_count);
    }

    void update_account(
        const evmc::address& address,
        std::optional<silkworm::Account> initial,
        std::optional<silkworm::Account> current) override {
        inner_state_.update_account(address, initial, current);
    }

    void update_account_code(
        const evmc::address& address,
        uint64_t incarnation,
        const evmc::bytes32& code_hash,
        silkworm::ByteView code) override {
        inner_state_.update_account_code(address, incarnation, code_hash, code);
    }

    void update_storage(
        const evmc::address& address,
        uint64_t incarnation,
        const evmc::bytes32& location,
        const evmc::bytes32& initial,
        const evmc::bytes32& current) override {
        inner_state_.update_storage(address, incarnation, location, initial, current);
    }

    void unwind_state_changes(BlockNum block_num) override {
        inner_state_.unwind_state_changes(block_num);
    }

  private:
    silkworm::State& inner_state_;
    const AccountsOverrides& accounts_overrides_;
    std::map<evmc::address, silkworm::ByteView> code_;
};

}  // namespace silkworm::rpc::state
