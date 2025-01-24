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

#include "local_state.hpp"

#include <silkworm/core/common/util.hpp>
#include <silkworm/db/state/accounts_domain.hpp>
#include <silkworm/db/state/code_domain.hpp>
#include <silkworm/db/state/schema_config.hpp>
#include <silkworm/db/state/storage_domain.hpp>

namespace silkworm::execution {

using namespace db::state;
using namespace datastore;

std::optional<Account> LocalState::read_account(const evmc::address& address) const noexcept {
    AccountsDomainGetLatestQuery query{
        data_store_.chaindata,
        tx_,
        data_store_.state_repository,
    };
    auto result = query.exec(address);
    if (result) {
        return std::move(result->value);
    }
    return std::nullopt;
}

ByteView LocalState::read_code(const evmc::address& address, const evmc::bytes32& /*code_hash*/) const noexcept {
    CodeDomainGetLatestQuery query{
        data_store_.chaindata,
        tx_,
        data_store_.state_repository,
    };
    auto result = query.exec(address);
    if (result) {
        static_assert(std::is_same_v<decltype(result->value), ByteView>);
        return result->value;
    }
    return ByteView{};
}

evmc::bytes32 LocalState::read_storage(
    const evmc::address& address,
    uint64_t /*incarnation*/,
    const evmc::bytes32& location) const noexcept {
    StorageDomainGetLatestQuery query{
        data_store_.chaindata,
        tx_,
        data_store_.state_repository,
    };
    auto result = query.exec({address, location});
    if (result) {
        return result->value;
    }
    return {};
}

uint64_t LocalState::previous_incarnation(const evmc::address& /*address*/) const noexcept {
    return 0;
}

std::optional<BlockHeader> LocalState::read_header(BlockNum block_num, const evmc::bytes32& block_hash) const noexcept {
    return data_model().read_header(block_num, block_hash);
}

bool LocalState::read_body(BlockNum block_num, const evmc::bytes32& block_hash, BlockBody& out) const noexcept {
    return data_model().read_body(block_hash, block_num, out);
}

std::optional<intx::uint256> LocalState::total_difficulty(BlockNum block_num, const evmc::bytes32& block_hash) const noexcept {
    return data_model().read_total_difficulty(block_num, block_hash);
}

evmc::bytes32 LocalState::state_root_hash() const {
    return evmc::bytes32{};
}

BlockNum LocalState::current_canonical_block() const {
    // This method should not be called by EVM::execute
    return 0;
}

std::optional<evmc::bytes32> LocalState::canonical_hash(BlockNum block_num) const {
    // This method should not be called by EVM::execute
    return data_model().read_canonical_header_hash(block_num);
}

void LocalState::update_account(
    const evmc::address& address,
    std::optional<Account> initial,
    std::optional<Account> current) {
    Step current_step = Step::from_txn_id(txn_id_);
    AccountsDomainPutQuery query{tx_, data_store_.state_db().accounts_domain()};
    // TODO: handle current = nullopt
    query.exec(address, *current, txn_id_, initial, current_step);
}

void LocalState::update_account_code(
    const evmc::address& address,
    uint64_t /*incarnation*/,
    const evmc::bytes32& /*code_hash*/,
    ByteView code) {
    Step current_step = Step::from_txn_id(txn_id_);
    CodeDomainPutQuery query{tx_, data_store_.state_db().code_domain()};
    // TODO: initial_code
    std::optional<ByteView> initial_code = std::nullopt;
    query.exec(address, code, txn_id_, initial_code, current_step);
}

void LocalState::update_storage(
    const evmc::address& address,
    uint64_t /*incarnation*/,
    const evmc::bytes32& location,
    const evmc::bytes32& initial,
    const evmc::bytes32& current) {
    Step current_step = Step::from_txn_id(txn_id_);
    StorageDomainPutQuery query{tx_, data_store_.state_db().storage_domain()};
    query.exec({address, location}, current, txn_id_, initial, current_step);
}

}  // namespace silkworm::execution
