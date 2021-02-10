/*
   Copyright 2020-2021 The Silkworm Authors

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

#include <silkworm/chain/validity.hpp>
#include <silkworm/execution/evm.hpp>
#include <silkworm/types/block.hpp>
#include <silkworm/types/receipt.hpp>
#include <silkworm/types/transaction.hpp>
#include <utility>
#include <vector>

namespace silkworm {

class ExecutionProcessor {
  public:
    ExecutionProcessor(const ExecutionProcessor&) = delete;
    ExecutionProcessor& operator=(const ExecutionProcessor&) = delete;

    ExecutionProcessor(const Block& block, IntraBlockState& state, const ChainConfig& config = kMainnetConfig);

    // precondition: txn.from must be recovered, otherwise kMissingSender will be returned
    ValidationResult validate_transaction(const Transaction& txn) const noexcept;

    // precondition: transaction must be valid
    Receipt execute_transaction(const Transaction& txn) noexcept;

    /// Execute the block, but do not write to the DB yet
    [[nodiscard]] std::pair<std::vector<Receipt>, ValidationResult> execute_block() noexcept;

    uint64_t cumulative_gas_used() const noexcept { return cumulative_gas_used_; }

    EVM& evm() noexcept { return evm_; }
    const EVM& evm() const noexcept { return evm_; }

  private:
    uint64_t available_gas() const noexcept;
    uint64_t refund_gas(const Transaction& txn, uint64_t gas_left) noexcept;

    void apply_rewards() noexcept;

    uint64_t cumulative_gas_used_{0};
    EVM evm_;
};

// Returns the intrinsic gas of a transaction.
// Refer to g0 in Section 6.2 "Execution" of the Yellow Paper.
intx::uint128 intrinsic_gas(const Transaction& txn, bool homestead, bool istanbul) noexcept;

}  // namespace silkworm

#endif  // SILKWORM_EXECUTION_PROCESSOR_H_
