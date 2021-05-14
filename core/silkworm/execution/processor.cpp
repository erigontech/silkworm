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

#include "processor.hpp"

#include <silkworm/chain/dao.hpp>
#include <silkworm/chain/intrinsic_gas.hpp>
#include <silkworm/chain/protocol_param.hpp>

#include "execution.hpp"

namespace silkworm {

ExecutionProcessor::ExecutionProcessor(const Block& block, IntraBlockState& state, const ChainConfig& config)
    : evm_{block, state, config} {}

ValidationResult ExecutionProcessor::validate_transaction(const Transaction& txn) const noexcept {
    if (!txn.from) {
        return ValidationResult::kMissingSender;
    }

    const IntraBlockState& state{evm_.state()};
    uint64_t nonce{state.get_nonce(*txn.from)};
    if (nonce != txn.nonce) {
        return ValidationResult::kWrongNonce;
    }

    intx::uint512 gas_cost{intx::umul(intx::uint256{txn.gas_limit}, txn.gas_price)};
    intx::uint512 v0{gas_cost + txn.value};

    if (state.get_balance(*txn.from) < v0) {
        return ValidationResult::kInsufficientFunds;
    }

    if (available_gas() < txn.gas_limit) {
        // Corresponds to the final condition of Eq (58) in Yellow Paper Section 6.2 "Execution".
        // The sum of the transaction’s gas limit and the gas utilized in this block prior
        // must be no greater than the block’s gas limit.
        return ValidationResult::kBlockGasLimitExceeded;
    }

    return ValidationResult::kOk;
}

Receipt ExecutionProcessor::execute_transaction(const Transaction& txn) noexcept {
    IntraBlockState& state{evm_.state()};
    evm_.state().clear_journal_and_substate();

    state.access_account(*txn.from);
    state.subtract_from_balance(*txn.from, txn.gas_limit * txn.gas_price);
    if (txn.to) {
        state.access_account(*txn.to);
        // EVM itself increments the nonce for contract creation
        state.set_nonce(*txn.from, txn.nonce + 1);
    }

    for (const AccessListEntry& ae : txn.access_list) {
        state.access_account(ae.account);
        for (const evmc::bytes32& key : ae.storage_keys) {
            state.access_storage(ae.account, key);
        }
    }

    const evmc_revision rev{evm_.revision()};

    const intx::uint128 g0{intrinsic_gas(txn, rev >= EVMC_HOMESTEAD, rev >= EVMC_ISTANBUL)};
    CallResult vm_res{evm_.execute(txn, txn.gas_limit - g0.lo)};

    uint64_t gas_used{txn.gas_limit - refund_gas(txn, vm_res.gas_left)};

    // award the miner
    state.add_to_balance(evm_.block().header.beneficiary, gas_used * txn.gas_price);

    evm_.state().destruct_suicides();
    if (rev >= EVMC_SPURIOUS_DRAGON) {
        evm_.state().destruct_touched_dead();
    }

    evm_.state().finalize_transaction();

    cumulative_gas_used_ += gas_used;

    return {
        txn.type,                         // type
        vm_res.status == EVMC_SUCCESS,    // success
        cumulative_gas_used_,             // cumulative_gas_used
        logs_bloom(evm_.state().logs()),  // bloom
        evm_.state().logs(),              // logs
    };
}

uint64_t ExecutionProcessor::available_gas() const noexcept {
    return evm_.block().header.gas_limit - cumulative_gas_used_;
}

uint64_t ExecutionProcessor::refund_gas(const Transaction& txn, uint64_t gas_left) noexcept {
    const evmc_revision rev{evm_.revision()};
    uint64_t refund{evm_.state().get_refund()};
    if (rev < EVMC_LONDON) {
        refund += fee::kRSelfDestruct * evm_.state().number_of_self_destructs();
    }
    const uint64_t max_refund_quotient{rev >= EVMC_LONDON ? param::kMaxRefundQuotientLondon
                                                          : param::kMaxRefundQuotientFrontier};
    const uint64_t max_refund{(txn.gas_limit - gas_left) / max_refund_quotient};
    refund = std::min(refund, max_refund);
    gas_left += refund;
    evm_.state().add_to_balance(*txn.from, gas_left * txn.gas_price);
    return gas_left;
}

std::pair<std::vector<Receipt>, ValidationResult> ExecutionProcessor::execute_block() noexcept {
    std::vector<Receipt> receipts{};

    uint64_t block_num{evm_.block().header.number};
    if (block_num == evm_.config().dao_block) {
        dao::transfer_balances(evm_.state());
    }

    cumulative_gas_used_ = 0;
    for (const Transaction& txn : evm_.block().transactions) {
        ValidationResult err{validate_transaction(txn)};
        if (err != ValidationResult::kOk) {
            return {receipts, err};
        }
        receipts.push_back(execute_transaction(txn));
    }

    apply_rewards();

    return {receipts, ValidationResult::kOk};
}

void ExecutionProcessor::apply_rewards() noexcept {
    const evmc_revision rev{evm_.revision()};
    intx::uint256 block_reward;
    if (rev >= EVMC_CONSTANTINOPLE) {
        block_reward = param::kBlockRewardConstantinople;
    } else if (rev >= EVMC_BYZANTIUM) {
        block_reward = param::kBlockRewardByzantium;
    } else {
        block_reward = param::kBlockRewardFrontier;
    }

    const uint64_t block_number{evm_.block().header.number};
    intx::uint256 miner_reward{block_reward};
    for (const BlockHeader& ommer : evm_.block().ommers) {
        intx::uint256 ommer_reward{((8 + ommer.number - block_number) * block_reward) >> 3};
        evm_.state().add_to_balance(ommer.beneficiary, ommer_reward);
        miner_reward += block_reward / 32;
    }

    evm_.state().add_to_balance(evm_.block().header.beneficiary, miner_reward);
}

}  // namespace silkworm
