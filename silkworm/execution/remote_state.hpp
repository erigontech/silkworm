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

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/db/chain/chain_storage.hpp>
#include <silkworm/db/chain/providers.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/db/kv/state_reader.hpp>

namespace silkworm::execution {

class AsyncRemoteState {
  public:
    explicit AsyncRemoteState(
        db::kv::api::Transaction& tx,
        const db::chain::ChainStorage& storage,
        TxnId txn_id)
        : storage_(storage), state_reader_(tx, txn_id) {}

    Task<std::optional<Account>> read_account(const evmc::address& address) const noexcept;

    Task<ByteView> read_code(const evmc::address& address, const evmc::bytes32& code_hash) const noexcept;

    Task<evmc::bytes32> read_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location) const noexcept;

    Task<uint64_t> previous_incarnation(const evmc::address& address) const noexcept;

    Task<std::optional<BlockHeader>> read_header(BlockNum block_num, const evmc::bytes32& block_hash) const noexcept;

    Task<bool> read_body(BlockNum block_num, const evmc::bytes32& block_hash, BlockBody& filled_body) const noexcept;

    Task<std::optional<intx::uint256>> total_difficulty(BlockNum block_num, const evmc::bytes32& block_hash) const noexcept;

    Task<evmc::bytes32> state_root_hash() const;

    Task<BlockNum> current_canonical_block() const;

    Task<std::optional<evmc::bytes32>> canonical_hash(BlockNum block_num) const;

  private:
    static std::unordered_map<evmc::bytes32, Bytes> code_;

    const db::chain::ChainStorage& storage_;
    db::kv::StateReader state_reader_;
};

class RemoteState : public State {
  public:
    explicit RemoteState(
        boost::asio::any_io_executor& executor,
        db::kv::api::Transaction& tx,
        const db::chain::ChainStorage& storage,
        TxnId txn_id)
        : executor_(executor), async_state_{tx, storage, txn_id} {}

    std::optional<Account> read_account(const evmc::address& address) const noexcept override;

    ByteView read_code(const evmc::address& address, const evmc::bytes32& code_hash) const noexcept override;

    evmc::bytes32 read_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location) const noexcept override;

    uint64_t previous_incarnation(const evmc::address& address) const noexcept override;

    std::optional<BlockHeader> read_header(BlockNum block_num, const evmc::bytes32& block_hash) const noexcept override;

    bool read_body(BlockNum block_num, const evmc::bytes32& block_hash, BlockBody& out) const noexcept override;

    std::optional<intx::uint256> total_difficulty(BlockNum block_num, const evmc::bytes32& block_hash) const noexcept override;

    evmc::bytes32 state_root_hash() const override;

    BlockNum current_canonical_block() const override;

    std::optional<evmc::bytes32> canonical_hash(BlockNum block_num) const override;

    void insert_block(const Block& /*block*/, const evmc::bytes32& /*hash*/) override {}

    void canonize_block(BlockNum /*block_num*/, const evmc::bytes32& /*block_hash*/) override {}

    void decanonize_block(BlockNum /*block_num*/) override {}

    void insert_receipts(BlockNum /*block_num*/, const std::vector<Receipt>& /*receipts*/) override {}

    void insert_call_traces(BlockNum /*block_num*/, const CallTraces& /*traces*/) override {}

    void begin_block(BlockNum /*block_num*/, size_t /*updated_accounts_count*/) override {}

    void update_account(
        const evmc::address& /*address*/,
        std::optional<Account> /*initial*/,
        std::optional<Account> /*current*/) override {}

    void update_account_code(
        const evmc::address& /*address*/,
        uint64_t /*incarnation*/,
        const evmc::bytes32& /*code_hash*/,
        ByteView /*code*/) override {}

    void update_storage(
        const evmc::address& /*address*/,
        uint64_t /*incarnation*/,
        const evmc::bytes32& /*location*/,
        const evmc::bytes32& /*initial*/,
        const evmc::bytes32& /*current*/) override {}

    void unwind_state_changes(BlockNum /*block_num*/) override {}

  private:
    boost::asio::any_io_executor executor_;
    AsyncRemoteState async_state_;
};

std::ostream& operator<<(std::ostream& out, const RemoteState& s);

}  // namespace silkworm::execution
