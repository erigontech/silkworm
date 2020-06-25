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

#include "evm.hpp"

#include "protocol_param.hpp"

namespace silkworm::eth {

EVM::EVM(IntraBlockState& state, evmc::address coinbase, uint64_t block_number)
    : state_{state}, coinbase_{coinbase}, block_number_{block_number} {}

CallResult EVM::create(const evmc::address&, std::string_view, uint64_t, const intx::uint256&) {
  CallResult res;
  // TODO(Andrew) implement
  // https://github.com/ethereum/EIPs/issues/684
  // https://eips.ethereum.org/EIPS/eip-170
  return res;
}

CallResult EVM::call(const evmc::address& caller, const evmc::address& recipient, std::string_view,
                     uint64_t gas, const intx::uint256& value) {
  CallResult res{.remaining_gas = gas, .status = EVMC_SUCCESS};

  if (stack_depth_ > param::kMaxStackDepth) {
    res.status = EVMC_CALL_DEPTH_EXCEEDED;
    return res;
  }

  if (state_.get_balance(caller) < value) {
    res.status = static_cast<evmc_status_code>(EVMC_BALANCE_TOO_LOW);
    return res;
  }

  if (!state_.exists(recipient)) {
    // TODO(Andrew) precompiles

    // https://eips.ethereum.org/EIPS/eip-161
    if (config_.has_spurious_dragon(block_number_) && value == 0) {
      return res;
    }
    state_.create(recipient, false);
  }

  state_.subtract_from_balance(caller, value);
  state_.add_to_balance(recipient, value);

  // TODO(Andrew) actually run the smart contract

  return res;
}

}  // namespace silkworm::eth
