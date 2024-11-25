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

namespace silkworm::db::state {

std::optional<Account> LocalState::read_account(const evmc::address& address) const noexcept {
    return db::read_account(txn_, address, block_num_ + 1);
}

ByteView LocalState::read_code(const evmc::address& /*address*/, const evmc::bytes32& code_hash) const noexcept {
    auto code_optional = db::read_code(txn_, code_hash);
    if (!code_optional) {
        return ByteView{};
    }
    return *code_optional;
}

evmc::bytes32 LocalState::read_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location) const noexcept {
    return db::read_storage(txn_, address, incarnation, location, block_num_ + 1);
}

uint64_t LocalState::previous_incarnation(const evmc::address& /*address*/) const noexcept {
    return 0;
}

std::optional<BlockHeader> LocalState::read_header(BlockNum block_num, const evmc::bytes32& block_hash) const noexcept {
    return data_model_.read_header(block_num, block_hash);
}

bool LocalState::read_body(BlockNum block_num, const evmc::bytes32& block_hash, BlockBody& out) const noexcept {
    return data_model_.read_body(block_hash, block_num, out);
}

std::optional<intx::uint256> LocalState::total_difficulty(BlockNum block_num, const evmc::bytes32& block_hash) const noexcept {
    return data_model_.read_total_difficulty(block_num, block_hash);
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
    return data_model_.read_canonical_header_hash(block_num);
}

}  // namespace silkworm::db::state
