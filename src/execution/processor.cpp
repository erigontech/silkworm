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

#include "processor.hpp"

#include <algorithm>
#include <intx/int128.hpp>
#include <limits>
#include <string_view>
#include <utility>

#include "protocol_param.hpp"

namespace silkworm {

static intx::uint128 intrinsic_gas(std::string_view data, bool contract_creation, bool homestead,
                                   bool eip2028) {
  intx::uint128 gas = fee::kGTransaction;
  if (contract_creation && homestead) {
    gas += fee::kGTxCreate;
  }

  if (data.empty()) {
    return gas;
  }

  intx::uint128 non_zero_bytes =
      std::count_if(data.begin(), data.end(), [](char c) { return c != 0; });

  uint64_t nonZeroGas{eip2028 ? fee::kGTxDataNonZeroEIP2028 : fee::kGTxDataNonZeroFrontier};
  gas += non_zero_bytes * nonZeroGas;

  intx::uint128 zero_bytes = data.length() - non_zero_bytes;
  gas += zero_bytes * fee::kGTxDataZero;

  return gas;
}

ExecutionProcessor::ExecutionProcessor(const BlockChain& chain, const Block& block,
                                       IntraBlockState& state)
    : evm_{chain, block, state} {}

ExecutionResult ExecutionProcessor::execute_transaction(const Transaction& txn) {
  ExecutionResult res;

  IntraBlockState& state = evm_.state();

  if (!txn.from || !state.exists(*txn.from)) {
    res.error = ValidationError::kMissingSender;
    return res;
  }

  uint64_t nonce = state.get_nonce(*txn.from);
  if (nonce != txn.nonce) {
    res.error = ValidationError::kInvalidNonce;
    return res;
  }

  uint64_t block_number = evm_.block().header.number;
  bool homestead = evm_.config().has_homestead(block_number);
  bool istanbul = evm_.config().has_istanbul(block_number);
  bool contract_creation = !txn.to;

  intx::uint128 g0 = intrinsic_gas(txn.data, contract_creation, homestead, istanbul);
  if (txn.gas_limit < g0) {
    res.error = ValidationError::kIntrinsicGas;
    return res;
  }

  intx::uint512 gas_cost = intx::umul(intx::uint256{txn.gas_limit}, txn.gas_price);
  intx::uint512 v0 = gas_cost + txn.value;

  if (state.get_balance(*txn.from) < v0) {
    res.error = ValidationError::kInsufficientFunds;
    return res;
  }

  if (available_gas() < txn.gas_limit) {
    res.error = ValidationError::kBlockGasLimitReached;
    return res;
  }

  state.subtract_from_balance(*txn.from, gas_cost.lo);
  state.set_nonce(*txn.from, nonce + 1);
  state.commit();
  evm_.substate().clear();

  CallResult vm_res{evm_.execute(txn, txn.gas_limit - g0.lo)};

  if (vm_res.status != EVMC_SUCCESS) {
    state.rollback();
    evm_.substate().clear();
  }

  uint64_t gas_left = refund_gas(txn, vm_res.gas_left);
  res.gas_used = txn.gas_limit - gas_left;

  // award the miner
  state.add_to_balance(evm_.block().header.beneficiary, res.gas_used * txn.gas_price);

  state.commit();

  gas_used_ += res.gas_used;

  res.receipt.post_state_or_status = vm_res.status == EVMC_SUCCESS;
  res.receipt.cumulative_gas_used = gas_used_;
  res.receipt.logs = evm_.substate().logs;
  // TODO[Byzantium] Bloom

  return res;
}

uint64_t ExecutionProcessor::available_gas() const {
  return evm_.block().header.gas_limit - gas_used_;
}

uint64_t ExecutionProcessor::refund_gas(const Transaction& txn, uint64_t gas_left) {
  IntraBlockState& state = evm_.state();

  uint64_t refund = std::min((txn.gas_limit - gas_left) / 2, evm_.substate().refund);
  gas_left += refund;
  state.add_to_balance(*txn.from, gas_left * txn.gas_price);

  return gas_left;
}

std::vector<Receipt> ExecutionProcessor::execute_block() {
  std::vector<Receipt> receipts;

  // TODO(Andrew) DAO block

  gas_used_ = 0;
  for (const Transaction& txn : evm_.block().transactions) {
    ExecutionResult res = execute_transaction(txn);
    if (res.error != ValidationError::kOk) {
      throw ExecutionError("ValidationError " + std::to_string(static_cast<int>(res.error)));
    }
    receipts.push_back(res.receipt);
  }

  apply_rewards();
  evm_.state().commit();

  return receipts;
}

void ExecutionProcessor::apply_rewards() {
  uint64_t block_number = evm_.block().header.number;
  intx::uint256 block_reward;
  if (evm_.config().has_constantinople(block_number)) {
    block_reward = param::kConstantinopleBlockReward;
  } else if (evm_.config().has_byzantium(block_number)) {
    block_reward = param::kByzantiumBlockReward;
  } else {
    block_reward = param::kFrontierBlockReward;
  }

  intx::uint256 miner_reward = block_reward;
  for (const BlockHeader& ommer : evm_.block().ommers) {
    intx::uint256 ommer_reward = (8 + ommer.number - block_number) * block_reward / 8;
    evm_.state().add_to_balance(ommer.beneficiary, ommer_reward);
    miner_reward += block_reward / 32;
  }

  evm_.state().add_to_balance(evm_.block().header.beneficiary, miner_reward);
}
}  // namespace silkworm
