/*
   Copyright 2024 The Silkworm Authors

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

#include <evmc/evmc.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/data_store.hpp>
#include <silkworm/db/datastore/common/step.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/execution/remote_state.hpp>

namespace silkworm::execution {

class DomainState : public State {
  public:
    explicit DomainState(
        TxnId txn_id,
        datastore::kvdb::RWTxn& tx,
        datastore::kvdb::DatabaseRef& database,
        snapshots::SnapshotRepository& blocks_repository,
        snapshots::SnapshotRepositoryROAccess& state_repository)
        : txn_id_{txn_id},
          tx_{tx},
          database_{database},
          state_repository_{state_repository},
          data_model_{db::DataModel{tx_, blocks_repository}} {}

    explicit DomainState(
        TxnId txn_id,
        datastore::kvdb::RWTxn& tx,
        datastore::kvdb::DatabaseRef& database,
        snapshots::SnapshotRepositoryROAccess& state_repository,
        db::DataModel& data_model)

        : txn_id_{txn_id},
          tx_{tx},
          database_{database},
          state_repository_{state_repository},
          data_model_{data_model} {}

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

    void insert_receipts(BlockNum block_num, const std::vector<Receipt>& receipts) override;

    void insert_call_traces(BlockNum /*block_num*/, const CallTraces& /*traces*/) override {}

    void begin_block(BlockNum /*block_num*/, size_t /*updated_accounts_count*/) override {}

    void update_account(
        const evmc::address& address,
        std::optional<Account> initial,
        std::optional<Account> current) override;

    void update_account_code(
        const evmc::address& address,
        uint64_t incarnation,
        const evmc::bytes32& code_hash,
        ByteView code) override;

    void update_storage(
        const evmc::address& address,
        uint64_t incarnation,
        const evmc::bytes32& location,
        const evmc::bytes32& initial,
        const evmc::bytes32& current) override;

    void unwind_state_changes(BlockNum /*block_num*/) override {}

  private:
    datastore::Step current_step() const;

    TxnId txn_id_;
    datastore::kvdb::RWTxn& tx_;
    datastore::kvdb::DatabaseRef& database_;
    snapshots::SnapshotRepositoryROAccess& state_repository_;
    db::DataModel data_model_;
};

}  // namespace silkworm::execution
