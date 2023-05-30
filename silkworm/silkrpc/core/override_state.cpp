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

#include <future>
#include <unordered_map>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>

namespace silkworm::rpc::state {

silkworm::Account get_account(const AccountOverrides& overrides) {
    auto overridden_account = silkworm::Account{};
    overridden_account.nonce = overrides.nonce.value_or(0);
    overridden_account.balance = overrides.balance.value_or(0);

    return overridden_account;
}

std::optional<silkworm::Account> OverrideState::read_account(const evmc::address& address) const noexcept {
    SILK_INFO << "OverrideState::read_account address=" << address << " start";
    std::cout << "*********** OverrideState::read_account address=: " << address << "\n";
    auto optional_account = inner_state_.read_account(address);
    auto it = state_overrides_.find(address);

    if (it != state_overrides_.end()) {
        auto overridden_account = get_account(it->second);
        auto account = optional_account.value_or(overridden_account);
        account.nonce = it->second.nonce.value_or(account.nonce);
        account.balance = it->second.balance.value_or(account.balance);
        std::cout << "*********** OverrideState::read_account account overridden " << account << "\n";
        optional_account = account;
    }
    return optional_account;
}

silkworm::ByteView OverrideState::read_code(const evmc::bytes32& code_hash) const noexcept {
    SILK_INFO << "OverrideState::read_code code_hash=" << code_hash << " start";
    // auto it = state_overrides_.find(address);
    // if (it != state_overrides_.end()) {
    //     return it->second.code;
    // }
    return inner_state_.read_code(code_hash);
}

evmc::bytes32 OverrideState::read_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location) const noexcept {
    SILK_INFO << "OverrideState::read_storage address=" << address << " incarnation=" << incarnation << " location=" << location << " start";
    auto storage_value = inner_state_.read_storage(address, incarnation, location);
    SILK_INFO << "OverrideState::read_storage storage_value=" << storage_value;
    return storage_value;
}

std::optional<silkworm::BlockHeader> OverrideState::read_header(uint64_t block_number, const evmc::bytes32& block_hash) const noexcept {
    SILK_INFO << "OverrideState::read_header block_number=" << block_number << " block_hash=" << block_hash;
    auto optional_header = inner_state_.read_header(block_number, block_hash);
    return optional_header;
}

bool OverrideState::read_body(uint64_t block_number, const evmc::bytes32& block_hash, silkworm::BlockBody& filled_body) const noexcept {
    SILK_INFO << "OverrideState::read_body block_number=" << block_number << " block_hash=" << block_hash;
    auto result = inner_state_.read_body(block_number, block_hash, filled_body);
    return result;
}

std::optional<intx::uint256> OverrideState::total_difficulty(uint64_t block_number, const evmc::bytes32& block_hash) const noexcept {
    SILK_INFO << "OverrideState::total_difficulty block_number=" << block_number << " block_hash=" << block_hash;
    auto optional_total_difficulty = inner_state_.total_difficulty(block_number, block_hash);
    SILK_INFO << "OverrideState::total_difficulty optional_total_difficulty=" << optional_total_difficulty.value_or(intx::uint256{});
    return optional_total_difficulty;
}

std::optional<evmc::bytes32> OverrideState::canonical_hash(uint64_t block_number) const {
    SILK_INFO << "OverrideState::canonical_hash block_number=" << block_number;
    auto optional_canonical_hash = inner_state_.canonical_hash(block_number);
    SILK_INFO << "OverrideState::canonical_hash optional_canonical_hash=" << optional_canonical_hash.value_or(evmc::bytes32{});
    return optional_canonical_hash;
}

}  // namespace silkworm::rpc::state
