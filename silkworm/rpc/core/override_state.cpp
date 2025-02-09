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

#include "override_state.hpp"

#include <bit>

#include <ethash/keccak.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc::state {

silkworm::Account get_account(const AccountOverrides& overrides, const std::optional<silkworm::Account>& optional_account) {
    auto overridden_account = optional_account.value_or(silkworm::Account{});
    if (overrides.nonce) {
        overridden_account.nonce = overrides.nonce.value();
    }
    if (overrides.balance) {
        overridden_account.balance = overrides.balance.value();
    }
    if (overrides.code_hash) {
        overridden_account.code_hash = overrides.code_hash.value();
    }

    return overridden_account;
}

OverrideState::OverrideState(silkworm::State& inner_state, const AccountsOverrides& accounts_overrides)
    : inner_state_{inner_state}, accounts_overrides_{accounts_overrides} {
    for (const auto& [key, value] : accounts_overrides_) {
        if (value.code) {
            code_.emplace(key, value.code.value());
        }
    }
}

std::optional<silkworm::Account> OverrideState::read_account(const evmc::address& address) const noexcept {
    SILK_DEBUG << "OverrideState::read_account address=" << address << " start";

    auto optional_account = inner_state_.read_account(address);
    auto it = accounts_overrides_.find(address);
    if (it != accounts_overrides_.end()) {
        auto overridden_account = get_account(it->second, optional_account);
        SILK_DEBUG << "OverrideState::read_account address=" << address << " account=" << overridden_account;
        optional_account = overridden_account;
    }

    return optional_account;
}

silkworm::ByteView OverrideState::read_code(const evmc::address& address, const evmc::bytes32& code_hash) const noexcept {
    SILK_DEBUG << "OverrideState::read_code code_hash=" << to_hex(code_hash) << " start";
    auto it = code_.find(address);
    if (it != code_.end()) {
        SILK_DEBUG << "OverrideState::read_code code_hash=" << to_hex(code_hash) << " code: " << it->second;
        return it->second;
    }
    return inner_state_.read_code(address, code_hash);
}

evmc::bytes32 OverrideState::read_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location) const noexcept {
    SILK_DEBUG << "OverrideState::read_storage address=" << address << " incarnation=" << incarnation << " location=" << to_hex(location) << " start";
    auto storage_value = inner_state_.read_storage(address, incarnation, location);
    SILK_DEBUG << "OverrideState::read_storage storage_value=" << to_hex(storage_value);
    return storage_value;
}

std::optional<silkworm::BlockHeader> OverrideState::read_header(BlockNum block_num, const evmc::bytes32& block_hash) const noexcept {
    SILK_DEBUG << "OverrideState::read_header block_num=" << block_num << " block_hash=" << to_hex(block_hash);
    auto optional_header = inner_state_.read_header(block_num, block_hash);
    return optional_header;
}

bool OverrideState::read_body(BlockNum block_num, const evmc::bytes32& block_hash, silkworm::BlockBody& out) const noexcept {
    SILK_DEBUG << "OverrideState::read_body block_num=" << block_num << " block_hash=" << to_hex(block_hash);
    auto result = inner_state_.read_body(block_num, block_hash, out);
    return result;
}

std::optional<intx::uint256> OverrideState::total_difficulty(BlockNum block_num, const evmc::bytes32& block_hash) const noexcept {
    SILK_DEBUG << "OverrideState::total_difficulty block_num=" << block_num << " block_hash=" << to_hex(block_hash);
    auto optional_total_difficulty = inner_state_.total_difficulty(block_num, block_hash);
    SILK_DEBUG << "OverrideState::total_difficulty optional_total_difficulty=" << optional_total_difficulty.value_or(intx::uint256{});
    return optional_total_difficulty;
}

std::optional<evmc::bytes32> OverrideState::canonical_hash(BlockNum block_num) const {
    SILK_DEBUG << "OverrideState::canonical_hash block_num=" << block_num;
    auto optional_canonical_hash = inner_state_.canonical_hash(block_num);
    SILK_DEBUG << "OverrideState::canonical_hash optional_canonical_hash=" << to_hex(optional_canonical_hash.value_or(evmc::bytes32{}));
    return optional_canonical_hash;
}

}  // namespace silkworm::rpc::state
