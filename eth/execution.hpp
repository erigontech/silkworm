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

#ifndef SILKWORM_ETH_EXECUTION_H_
#define SILKWORM_ETH_EXECUTION_H_

#include <stdint.h>

#include <stdexcept>
#include <string>

#include "block.hpp"
#include "evm.hpp"
#include "receipt.hpp"
#include "transaction.hpp"

namespace silkworm::eth {

enum class ValidationError {
  kOk = 0,
  kMissingSender,
  kInvalidNonce,
  kIntrinsicGas,
  kInsufficientFunds,
  kBlockGasLimitReached,
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

  ExecutionProcessor(IntraBlockState& state, const Block& block);

  // precondition: txn.from must be recovered
  ExecutionResult execute_transaction(const Transaction& txn);

 private:
  uint64_t refund_gas(const Transaction& txn, uint64_t gas_left);

  uint64_t gas_pool_{0};
  uint64_t cumulative_gas_used_{0};
  EVM evm_;
};

}  // namespace silkworm::eth

#endif  // SILKWORM_ETH_EXECUTION_H_
