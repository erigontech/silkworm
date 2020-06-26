/*
   Copyright 2020 The Silkworm Authors

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

// TODO(Andrew) implement

#include "intra_block_state.hpp"

namespace silkworm::eth {

bool IntraBlockState::exists(const evmc::address&) const { return false; }

void IntraBlockState::create(const evmc::address&, bool) {}

intx::uint256 IntraBlockState::get_balance(const evmc::address& address) const {
  auto it = accounts_.find(address);
  return it == accounts_.end() ? intx::uint256{} : it->second.balance;
}

void IntraBlockState::add_to_balance(const evmc::address& address, const intx::uint256& addend) {
  accounts_[address].balance += addend;
}

void IntraBlockState::subtract_from_balance(const evmc::address& address,
                                            const intx::uint256& subtrahend) {
  accounts_[address].balance -= subtrahend;
}

uint64_t IntraBlockState::get_nonce(const evmc::address&) const { return 0; }

void IntraBlockState::set_nonce(const evmc::address&, uint64_t) {}

std::string_view IntraBlockState::get_code(const evmc::address&) const { return {}; }

evmc::bytes32 IntraBlockState::get_code_hash(const evmc::address&) const { return {}; }

uint64_t IntraBlockState::get_refund() const { return 0; }

void IntraBlockState::add_refund(uint64_t) {}

void IntraBlockState::subtract_refund(uint64_t) {}

evmc::bytes32 IntraBlockState::get_storage(const evmc::address&, const evmc::bytes32&) const {
  return {};
}

void IntraBlockState::set_storage(const evmc::address&, const evmc::bytes32&,
                                  const evmc::bytes32&) {}

}  // namespace silkworm::eth
