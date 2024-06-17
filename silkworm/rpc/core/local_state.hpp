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

#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/mdbx/mdbx.hpp>
#include <silkworm/rpc/core/state_reader.hpp>

namespace silkworm::rpc::state {

class LocalState : public silkworm::State {
  public:
    explicit LocalState(BlockNum block_number, mdbx::env chaindata_env)
        : block_number_{block_number}, txn_{std::move(chaindata_env)} {}

    std::optional<silkworm::Account> read_account(const evmc::address& address) const noexcept override;

    silkworm::ByteView read_code(const evmc::bytes32& code_hash) const noexcept override;

    evmc::bytes32 read_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location) const noexcept override;

    uint64_t previous_incarnation(const evmc::address& address) const noexcept override;

    std::optional<silkworm::BlockHeader> read_header(BlockNum block_number, const evmc::bytes32& block_hash) const noexcept override;

    bool read_body(BlockNum block_number, const evmc::bytes32& block_hash, silkworm::BlockBody& out) const noexcept override;

    std::optional<intx::uint256> total_difficulty(BlockNum block_number, const evmc::bytes32& block_hash) const noexcept override;

    evmc::bytes32 state_root_hash() const override;

    BlockNum current_canonical_block() const override;

    std::optional<evmc::bytes32> canonical_hash(BlockNum block_number) const override;

    void insert_block(const silkworm::Block& /*block*/, const evmc::bytes32& /*hash*/) override {}

    void canonize_block(BlockNum /*block_number*/, const evmc::bytes32& /*block_hash*/) override {}

    void decanonize_block(BlockNum /*block_number*/) override {}

    void insert_receipts(BlockNum /*block_number*/, const std::vector<silkworm::Receipt>& /*receipts*/) override {}

    void insert_call_traces(BlockNum /*block_number*/, const CallTraces& /*traces*/) override {}

    void begin_block(BlockNum /*block_number*/, size_t /*updated_accounts_count*/) override {}

    void update_account(
        const evmc::address& /*address*/,
        std::optional<silkworm::Account> /*initial*/,
        std::optional<silkworm::Account> /*current*/) override {}

    void update_account_code(
        const evmc::address& /*address*/,
        uint64_t /*incarnation*/,
        const evmc::bytes32& /*code_hash*/,
        silkworm::ByteView /*code*/) override {}

    void update_storage(
        const evmc::address& /*address*/,
        uint64_t /*incarnation*/,
        const evmc::bytes32& /*location*/,
        const evmc::bytes32& /*initial*/,
        const evmc::bytes32& /*current*/) override {}

    void unwind_state_changes(BlockNum /*block_number*/) override {}

  private:
    BlockNum block_number_;
    mutable db::ROTxnManaged txn_;
};

}  // namespace silkworm::rpc::state
