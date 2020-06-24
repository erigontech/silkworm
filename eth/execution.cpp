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

#include "execution.hpp"

#include <algorithm>
#include <intx/int128.hpp>
#include <limits>
#include <string_view>
#include <utility>

#include "protocol_params.hpp"

namespace {

using namespace silkworm::eth;

intx::uint128 IntrinsicGas(std::string_view data, bool contract_creation, bool homestead,
                           bool eip2028) {
  intx::uint128 gas = params::kTxGas;
  if (contract_creation && homestead) {
    gas = params::kTxGasContractCreation;
  }

  if (data.empty()) {
    return gas;
  }

  intx::uint128 non_zero_bytes =
      std::count_if(data.begin(), data.end(), [](char c) { return c != 0; });

  uint64_t nonZeroGas{eip2028 ? params::kTxDataNonZeroGasEIP2028
                              : params::kTxDataNonZeroGasFrontier};
  gas += non_zero_bytes * nonZeroGas;

  intx::uint128 zero_bytes = data.length() - non_zero_bytes;
  gas += zero_bytes * params::kTxDataZeroGas;

  return gas;
}

}  // namespace

namespace silkworm::eth {

ExecutionProcessor::ExecutionProcessor(IntraBlockState& state, Address coinbase,
                                       uint64_t block_number)
    : evm_{state, coinbase, block_number} {}

ExecutionResult ExecutionProcessor::ExecuteTransaction(const Transaction& txn) {
  ExecutionResult res;

  IntraBlockState& state = evm_.state();

  if (!txn.from || !state.Exists(*txn.from)) {
    res.error = ValidationError::kMissingSender;
    return res;
  }

  uint64_t nonce = state.GetNonce(*txn.from);
  if (nonce != txn.nonce) {
    res.error = ValidationError::kInvalidNonce;
    return res;
  }

  bool homestead = evm_.config().IsHomestead(evm_.block_number());
  bool istanbul = evm_.config().IsIstanbul(evm_.block_number());
  bool contract_creation = !txn.to;

  intx::uint128 g0 = IntrinsicGas(txn.data, contract_creation, homestead, istanbul);
  if (txn.gas_limit < g0) {
    res.error = ValidationError::kIntrinsicGas;
    return res;
  }

  intx::uint512 gas_cost = intx::umul(intx::uint256{txn.gas_limit}, txn.gas_price);
  intx::uint512 v0 = gas_cost + txn.value;

  if (state.GetBalance(*txn.from) < v0) {
    res.error = ValidationError::kInsufficientFunds;
    return res;
  }

  if (gas_pool_ < txn.gas_limit) {
    res.error = ValidationError::kBlockGasLimitReached;
    return res;
  }

  state.SubBalance(*txn.from, gas_cost.lo);

  uint64_t g = txn.gas_limit - g0.lo;
  CallResult vm_res;
  if (contract_creation) {
    // Create itself increments the nonce
    vm_res = evm_.Create(*txn.from, txn.data, g, txn.value);
  } else {
    state.SetNonce(*txn.from, nonce + 1);
    vm_res = evm_.Call(*txn.from, *txn.to, txn.data, g, txn.value);
  }

  res.success = vm_res.status == EVMC_SUCCESS;

  uint64_t remaining_gas = RefundGas(txn, vm_res.remaining_gas);
  res.used_gas = txn.gas_limit - remaining_gas;

  // award the miner
  state.AddBalance(evm_.coinbase(), res.used_gas * txn.gas_price);

  return res;
}

uint64_t ExecutionProcessor::RefundGas(const Transaction& txn, uint64_t remaining_gas) {
  IntraBlockState& state = evm_.state();

  uint64_t refund = std::min((txn.gas_limit - remaining_gas) / 2, state.GetRefund());
  remaining_gas += refund;
  gas_pool_ += remaining_gas;
  state.AddBalance(*txn.from, remaining_gas * txn.gas_price);

  return remaining_gas;
}

}  // namespace silkworm::eth
