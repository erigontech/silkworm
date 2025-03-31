// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "local_state.hpp"

#include <silkworm/core/common/util.hpp>
#include <silkworm/db/state/accounts_domain.hpp>
#include <silkworm/db/state/code_domain.hpp>
#include <silkworm/db/state/storage_domain.hpp>

namespace silkworm::execution {

using namespace db::state;
using namespace datastore;

std::optional<Account> LocalState::read_account(const evmc::address& address) const noexcept {
    return query_as_of<AccountsDomainGetAsOfQuery>().exec(address, txn_id_).value_or(std::nullopt);
}

ByteView LocalState::read_code(const evmc::address& address, const evmc::bytes32& /*code_hash*/) const noexcept {
    if (code_.contains(address)) {
        return code_[address];  // NOLINT(runtime/arrays)
    }

    auto result = query_as_of<CodeDomainGetAsOfQuery>().exec(address, txn_id_);
    if (result) {
        auto [it, _] = code_.emplace(address, std::move(*result));
        return it->second;
    }
    return ByteView{};
}

evmc::bytes32 LocalState::read_storage(const evmc::address& address, uint64_t /*incarnation*/, const evmc::bytes32& location) const noexcept {
    auto result = query_as_of<StorageDomainGetAsOfQuery>().exec({address, location}, txn_id_);
    return result.value_or(evmc::bytes32{});
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

}  // namespace silkworm::execution
