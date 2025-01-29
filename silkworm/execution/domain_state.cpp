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

#include "domain_state.hpp"

#include <silkworm/core/common/util.hpp>
#include <silkworm/db/state/accounts_domain.hpp>
#include <silkworm/db/state/code_domain.hpp>
#include <silkworm/db/state/schema_config.hpp>
#include <silkworm/db/state/storage_domain.hpp>

namespace silkworm::execution {

using namespace db::state;
using namespace datastore;

// TODO:
//  - implement: state_root_hash, canonize_block, decanonize_block (optional)
//  - implement insert_call_traces (mandatory)
//  - add begin_txn method (replacing begin_block?)
//  - insert_receipts should write to domain receipts table db::state::kDomainNameReceipts
//  - add buffer saving previous steps for values in accounts, code and storage domains - for updates
//  - extend transaction to include txn_id, or
//  - add base_txn_id to block and get_txn_by_id method

std::optional<Account> DomainState::read_account(const evmc::address& address) const noexcept {
    AccountsDomainGetLatestQuery query{database_, tx_, state_repository_};
    auto result = query.exec(address);
    if (result) {
        return std::move(result->value);
    }
    return std::nullopt;
}

ByteView DomainState::read_code(const evmc::address& address, const evmc::bytes32& /*code_hash*/) const noexcept {
    CodeDomainGetLatestQuery query{database_, tx_, state_repository_};
    auto result = query.exec(address);
    if (result) {
        return std::move(result->value);
    }
    return ByteView{};
}

evmc::bytes32 DomainState::read_storage(
    const evmc::address& address,
    uint64_t /*incarnation*/,
    const evmc::bytes32& location) const noexcept {
    StorageDomainGetLatestQuery query{database_, tx_, state_repository_};
    auto result = query.exec({address, location});
    if (result) {
        return std::move(result->value);
    }
    return {};
}

uint64_t DomainState::previous_incarnation(const evmc::address& address) const noexcept {
    auto prev_incarnation = db::read_previous_incarnation(tx_, address);
    return prev_incarnation.value_or(0);
}

std::optional<BlockHeader> DomainState::read_header(BlockNum block_num, const evmc::bytes32& block_hash) const noexcept {
    return data_model_.read_header(block_num, block_hash);
}

bool DomainState::read_body(BlockNum block_num, const evmc::bytes32& block_hash, BlockBody& out) const noexcept {
    return data_model_.read_body(block_hash, block_num, out);
}

std::optional<intx::uint256> DomainState::total_difficulty(BlockNum block_num, const evmc::bytes32& block_hash) const noexcept {
    return data_model_.read_total_difficulty(block_num, block_hash);
}

evmc::bytes32 DomainState::state_root_hash() const {
    // TODO: implement
    return evmc::bytes32{};
}

BlockNum DomainState::current_canonical_block() const {
    auto head = db::read_canonical_head(tx_);
    return std::get<0>(head);
}

std::optional<evmc::bytes32> DomainState::canonical_hash(BlockNum block_num) const {
    return data_model_.read_canonical_header_hash(block_num);
}

void DomainState::insert_receipts(BlockNum block_num, const std::vector<Receipt>& receipts) {
    // TODO: write to domain receipts table db::state::kDomainNameReceipts
    db::write_receipts(tx_, receipts, block_num);
}

void DomainState::update_account(
    const evmc::address& address,
    std::optional<Account> original,
    std::optional<Account> current) {
    if (!original) {
        AccountsDomainGetLatestQuery query_prev{database_, tx_, state_repository_};
        auto result_prev = query_prev.exec(address);
        if (result_prev) {
            original = result_prev->value;
        }
    }

    auto prev_step = Step{0};  // TODO: JG remove

    if (current) {
        AccountsDomainPutQuery query{database_, tx_};
        query.exec(address, *current, txn_id_, original, prev_step);
    } else {
        AccountsDomainDeleteQuery query{tx_, database_.domain(kDomainNameAccounts)};
        query.exec(address, txn_id_, original, prev_step);
    }
}

void DomainState::update_account_code(
    const evmc::address& address,
    uint64_t /*incarnation*/,
    const evmc::bytes32& /*code_hash*/,
    ByteView code) {
    CodeDomainGetLatestQuery query_prev{database_, tx_, state_repository_};
    auto result_prev = query_prev.exec(address);

    Step prev_step{0};
    std::optional<ByteView> original_code = std::nullopt;
    if (result_prev) {
        prev_step = result_prev->step;
        original_code = result_prev->value;
    }

    CodeDomainPutQuery query{database_, tx_};
    query.exec(address, code, txn_id_, original_code, prev_step);
}

void DomainState::update_storage(
    const evmc::address& address,
    uint64_t /*incarnation*/,
    const evmc::bytes32& location,
    const evmc::bytes32& initial,
    const evmc::bytes32& current) {
    evmc::bytes32 original_value{};

    if (initial == evmc::bytes32{}) {
        StorageDomainGetLatestQuery query_prev{database_, tx_, state_repository_};
        auto result_prev = query_prev.exec({address, location});
        if (result_prev) {
            original_value = result_prev->value;
        }
    } else {
        original_value = initial;
    }

    Step prev_step{0};

    StorageDomainPutQuery query{database_, tx_};
    query.exec({address, location}, current, txn_id_, original_value, prev_step);
}

}  // namespace silkworm::execution
