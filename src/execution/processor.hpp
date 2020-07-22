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

#ifndef SILKWORM_EXECUTION_PROCESSOR_H_
#define SILKWORM_EXECUTION_PROCESSOR_H_

#include <stdint.h>

#include <stdexcept>
#include <vector>

#include "evm.hpp"
#include "types/block.hpp"
#include "types/receipt.hpp"
#include "types/transaction.hpp"

namespace silkworm {

enum class ValidationError {
  kOk = 0,
  kMissingSender,
  kInvalidNonce,
  kIntrinsicGas,
  kInsufficientFunds,
  kBlockGasLimitReached,
};

class ExecutionError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

struct ExecutionResult {
  ValidationError error{ValidationError::kOk};
  uint64_t gas_used{0};
  Receipt receipt;
};

class ExecutionProcessor {
 public:
  ExecutionProcessor(const ExecutionProcessor&) = delete;
  ExecutionProcessor& operator=(const ExecutionProcessor&) = delete;

  ExecutionProcessor(const BlockChain& chain, const Block& block, IntraBlockState& state);

  // precondition: txn.from must be recovered
  ExecutionResult execute_transaction(const Transaction& txn);

  std::vector<Receipt> execute_block();

  uint64_t gas_used() const { return gas_used_; }

 private:
  uint64_t available_gas() const;
  uint64_t refund_gas(const Transaction& txn, uint64_t gas_left);

  void apply_rewards();

  uint64_t gas_used_{0};
  EVM evm_;
};
}  // namespace silkworm

#endif  // SILKWORM_EXECUTION_PROCESSOR_H_
