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

#ifndef SILKWORM_EXECUTION_PROCESSOR_HPP_
#define SILKWORM_EXECUTION_PROCESSOR_HPP_

#include <cstdint>
#include <vector>

#include <silkworm/consensus/engine.hpp>
#include <silkworm/execution/evm.hpp>
#include <silkworm/state/state.hpp>
#include <silkworm/types/block.hpp>
#include <silkworm/types/receipt.hpp>
#include <silkworm/types/transaction.hpp>

namespace silkworm {

class ExecutionProcessor {
  public:
    ExecutionProcessor(const ExecutionProcessor&) = delete;
    ExecutionProcessor& operator=(const ExecutionProcessor&) = delete;

    ExecutionProcessor(const Block& block, consensus::IEngine& engine, State& state, const ChainConfig& config);

    // Preconditions:
    // 1) consensus' pre_validate_transaction(txn) must return kOk
    // 2) txn.from must be recovered, otherwise kMissingSender will be returned
    ValidationResult validate_transaction(const Transaction& txn) const noexcept;

    // Execute a transaction, but do not write to the DB yet.
    // Precondition: transaction must be valid.
    void execute_transaction(const Transaction& txn, Receipt& receipt) noexcept;

    //! \brief Execute the block and write the result to the DB.
    //! \remarks Warning: This method does not verify state root; pre-Byzantium receipt root isn't validated either.
    //! \pre consensus_engine's pre_validate_block(block) must return kOk.
    [[nodiscard]] ValidationResult execute_and_write_block(std::vector<Receipt>& receipts) noexcept;

    uint64_t cumulative_gas_used() const noexcept { return cumulative_gas_used_; }

    EVM& evm() noexcept { return evm_; }
    const EVM& evm() const noexcept { return evm_; }

  private:
    /// Execute the block, but do not write to the DB yet.
    /// Does not perform any post-execution validation (for example, receipt root is not checked).
    /// Precondition: pre_validate_block(block) must return kOk.
    [[nodiscard]] ValidationResult execute_block_no_post_validation(std::vector<Receipt>& receipts) noexcept;

    uint64_t available_gas() const noexcept;
    uint64_t refund_gas(const Transaction& txn, uint64_t gas_left) noexcept;

    uint64_t cumulative_gas_used_{0};
    IntraBlockState state_;
    consensus::IEngine& consensus_engine_;
    EVM evm_;
};

}  // namespace silkworm

#endif  // SILKWORM_EXECUTION_PROCESSOR_HPP_
