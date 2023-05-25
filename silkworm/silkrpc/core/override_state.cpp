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

std::optional<silkworm::Account> OverrideState::read_account(const evmc::address& address) const noexcept {
    SILK_DEBUG << "OverrideState::read_account address=" << address << " start";
    auto optional_account = inner_state_.read_account(address);

    return optional_account;
}

// silkworm::ByteView OverrideState::read_code(const evmc::bytes32& code_hash) const noexcept {
//     SILK_DEBUG << "OverrideState::read_code code_hash=" << code_hash << " start";
//     auto code = inner_state_.read_code(code_hash);
//     return code;
// }

evmc::bytes32 OverrideState::read_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location) const noexcept {
    SILK_INFO << "OverrideState::read_storage address=" << address << " incarnation=" << incarnation << " location=" << location << " start";
    auto storage_value = inner_state_.read_storage(address, incarnation, location);
    SILK_INFO << "OverrideState::read_storage storage_value=" << storage_value;
    return storage_value;
}

// uint64_t OverrideState::previous_incarnation(const evmc::address& address) const noexcept {
//     SILK_DEBUG << "OverrideState::previous_incarnation address=" << address;
//     return 0;
// }

std::optional<silkworm::BlockHeader> OverrideState::read_header(uint64_t block_number, const evmc::bytes32& block_hash) const noexcept {
    SILK_DEBUG << "OverrideState::read_header block_number=" << block_number << " block_hash=" << block_hash;
    auto optional_header = inner_state_.read_header(block_number, block_hash);
    return optional_header;
}

bool OverrideState::read_body(uint64_t block_number, const evmc::bytes32& block_hash, silkworm::BlockBody& filled_body) const noexcept {
    SILK_DEBUG << "OverrideState::read_body block_number=" << block_number << " block_hash=" << block_hash;
    auto result = inner_state_.read_body(block_number, block_hash, filled_body);
    return result;
}

std::optional<intx::uint256> OverrideState::total_difficulty(uint64_t block_number, const evmc::bytes32& block_hash) const noexcept {
    SILK_INFO << "OverrideState::total_difficulty block_number=" << block_number << " block_hash=" << block_hash;
    auto optional_total_difficulty = inner_state_.total_difficulty(block_number, block_hash);
    SILK_INFO << "OverrideState::read_storage optional_total_difficulty=" << optional_total_difficulty.value_or(intx::uint256{});
    return optional_total_difficulty;
}

// evmc::bytes32 OverrideState::state_root_hash() const {
//     SILK_DEBUG << "OverrideState::state_root_hash";
//     return evmc::bytes32{};
// }

// uint64_t OverrideState::current_canonical_block() const {
//     SILK_DEBUG << "OverrideState::current_canonical_block";
//     return 0;
// }

// std::optional<evmc::bytes32> OverrideState::canonical_hash(uint64_t block_number) const {
//     SILK_DEBUG << "OverrideState::canonical_hash block_number=" << block_number;
//     return std::nullopt;
// }

}  // namespace silkworm::rpc::state
