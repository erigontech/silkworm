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

#include <evmc/evmc.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/data_store.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>

namespace silkworm::execution {

class LocalState : public State {
  public:
    explicit LocalState(
        std::optional<TxnId> txn_id,
        db::DataStoreRef data_store)
        : txn_id_{txn_id},
          data_store_{std::move(data_store)},
          tx_{data_store_.chaindata.access_ro().start_ro_tx()} {}

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
    db::DataModel data_model() const {
        return db::DataModelFactory{data_store_}(tx_);
    }

    std::optional<TxnId> txn_id_;
    db::DataStoreRef data_store_;
    mutable datastore::kvdb::ROTxnManaged tx_;

    mutable std::unordered_map<evmc::address, Bytes> code_;
};

}  // namespace silkworm::execution
