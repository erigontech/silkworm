/*
   Copyright 2022 The Silkworm Authors

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

#include <cassert>

#include <silkworm/core/chain/dao.hpp>
#include <silkworm/core/protocol/intrinsic_gas.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/trie/vector_root.hpp>

namespace silkworm {

ExecutionProcessor::ExecutionProcessor(const Block& block, protocol::IRuleSet& rule_set, State& state,
                                       const ChainConfig& config)
    : state_{state}, rule_set_{rule_set}, evm_{block, state_, config} {
    evm_.beneficiary = rule_set.get_beneficiary(block.header);
}

ValidationResult ExecutionProcessor::validate_transaction(const Transaction& txn) const noexcept {
    if (!txn.from) {
        return ValidationResult::kMissingSender;
    }

    if (state_.get_code_hash(*txn.from) != kEmptyHash) {
        return ValidationResult::kSenderNoEOA;  // EIP-3607
    }

    const uint64_t nonce{state_.get_nonce(*txn.from)};
    if (nonce != txn.nonce) {
        return ValidationResult::kWrongNonce;
    }

    // See YP, Eq (61) in Section 6.2 "Execution"
    const intx::uint512 v0{txn.maximum_gas_cost() + txn.value};
    if (state_.get_balance(*txn.from) < v0) {
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

void ExecutionProcessor::execute_transaction(const Transaction& txn, Receipt& receipt) noexcept {
    assert(validate_transaction(txn) == ValidationResult::kOk);

    // Optimization: since receipt.logs might have some capacity, let's reuse it.
    std::swap(receipt.logs, state_.logs());

    state_.clear_journal_and_substate();

    assert(txn.from);
    state_.access_account(*txn.from);

    if (txn.to) {
        state_.access_account(*txn.to);
        // EVM itself increments the nonce for contract creation
        state_.set_nonce(*txn.from, txn.nonce + 1);
    }

    for (const AccessListEntry& ae : txn.access_list) {
        state_.access_account(ae.account);
        for (const evmc::bytes32& key : ae.storage_keys) {
            state_.access_storage(ae.account, key);
        }
    }

    const evmc_revision rev{evm_.revision()};
    if (rev >= EVMC_SHANGHAI) {
        // EIP-3651: Warm COINBASE
        state_.access_account(evm_.beneficiary);
    }

    // EIP-1559 normal gas cost
    const intx::uint256 base_fee_per_gas{evm_.block().header.base_fee_per_gas.value_or(0)};
    const intx::uint256 effective_gas_price{txn.effective_gas_price(base_fee_per_gas)};
    state_.subtract_from_balance(*txn.from, txn.gas_limit * effective_gas_price);

    // EIP-4844 data gas cost (calc_data_fee)
    const intx::uint256 data_gas_price{evm_.block().header.data_gas_price().value_or(0)};
    state_.subtract_from_balance(*txn.from, txn.total_data_gas() * data_gas_price);

    const intx::uint128 g0{protocol::intrinsic_gas(txn, rev)};
    assert(g0 <= UINT64_MAX);  // true due to the precondition (transaction must be valid)

    const CallResult vm_res{evm_.execute(txn, txn.gas_limit - static_cast<uint64_t>(g0))};

    const uint64_t gas_used{txn.gas_limit - refund_gas(txn, vm_res.gas_left, vm_res.gas_refund)};

    // award the fee recipient
    const intx::uint256 priority_fee_per_gas{txn.priority_fee_per_gas(base_fee_per_gas)};
    state_.add_to_balance(evm_.beneficiary, priority_fee_per_gas * gas_used);

    state_.destruct_suicides();
    if (rev >= EVMC_SPURIOUS_DRAGON) {
        state_.destruct_touched_dead();
    }

    state_.finalize_transaction();

    cumulative_gas_used_ += gas_used;

    receipt.type = txn.type;
    receipt.success = vm_res.status == EVMC_SUCCESS;
    receipt.cumulative_gas_used = cumulative_gas_used_;
    receipt.bloom = logs_bloom(state_.logs());
    std::swap(receipt.logs, state_.logs());
}

uint64_t ExecutionProcessor::available_gas() const noexcept {
    return evm_.block().header.gas_limit - cumulative_gas_used_;
}

uint64_t ExecutionProcessor::refund_gas(const Transaction& txn, uint64_t gas_left, uint64_t gas_refund) noexcept {
    const evmc_revision rev{evm_.revision()};

    const uint64_t max_refund_quotient{rev >= EVMC_LONDON ? protocol::kMaxRefundQuotientLondon
                                                          : protocol::kMaxRefundQuotientFrontier};
    const uint64_t max_refund{(txn.gas_limit - gas_left) / max_refund_quotient};
    uint64_t refund = std::min(gas_refund, max_refund);
    gas_left += refund;

    const intx::uint256 base_fee_per_gas{evm_.block().header.base_fee_per_gas.value_or(0)};
    const intx::uint256 effective_gas_price{txn.effective_gas_price(base_fee_per_gas)};
    state_.add_to_balance(*txn.from, gas_left * effective_gas_price);

    return gas_left;
}

ValidationResult ExecutionProcessor::execute_block_no_post_validation(std::vector<Receipt>& receipts) noexcept {
    const Block& block{evm_.block()};

    if (block.header.number == evm_.config().dao_block) {
        dao::transfer_balances(state_);
    }

    cumulative_gas_used_ = 0;

    receipts.resize(block.transactions.size());
    auto receipt_it{receipts.begin()};
    for (const auto& txn : block.transactions) {
        const ValidationResult err{validate_transaction(txn)};
        if (err != ValidationResult::kOk) {
            return err;
        }
        execute_transaction(txn, *receipt_it);
        ++receipt_it;
    }

    rule_set_.finalize(state_, block);

    if (evm_.revision() >= EVMC_SPURIOUS_DRAGON) {
        state_.destruct_touched_dead();
    }

    return ValidationResult::kOk;
}

ValidationResult ExecutionProcessor::execute_and_write_block(std::vector<Receipt>& receipts) noexcept {
    if (const ValidationResult res{execute_block_no_post_validation(receipts)}; res != ValidationResult::kOk) {
        return res;
    }

    const auto& header{evm_.block().header};

    if (cumulative_gas_used() != header.gas_used) {
        return ValidationResult::kWrongBlockGas;
    }

    if (evm_.revision() >= EVMC_BYZANTIUM) {
        static constexpr auto kEncoder = [](Bytes& to, const Receipt& r) { rlp::encode(to, r); };
        evmc::bytes32 receipt_root{trie::root_hash(receipts, kEncoder)};
        if (receipt_root != header.receipts_root) {
            return ValidationResult::kWrongReceiptsRoot;
        }
    }

    Bloom bloom{};  // zero initialization
    for (const Receipt& receipt : receipts) {
        join(bloom, receipt.bloom);
    }
    if (bloom != header.logs_bloom) {
        return ValidationResult::kWrongLogsBloom;
    }

    state_.write_to_db(header.number);

    return ValidationResult::kOk;
}

}  // namespace silkworm
