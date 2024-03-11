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

#include <evmone/test/state/state.hpp>

#include <silkworm/core/protocol/intrinsic_gas.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/trie/vector_root.hpp>

namespace silkworm {
static thread_local evmone::MegaContext e1_ctx;

class StateView : public evmone::state::StateView {
    IntraBlockState& state_;
    EVM& evm_;

  public:
    explicit StateView(IntraBlockState& state, EVM& evm) noexcept : state_{state}, evm_{evm} {}

    std::optional<Account> get_account(evmc::address addr) const noexcept override {
        const auto* obj = state_.get_object(addr);
        if (obj == nullptr || !obj->current.has_value())
            return std::nullopt;

        const auto& cur = *obj->current;
        return Account{.nonce = cur.nonce, .balance = cur.balance, .code_hash = cur.code_hash};
    }

    evmone::bytes get_account_code(evmc::address addr) const noexcept override {
        return evmone::bytes{state_.get_code(addr)};
    }

    evmc::bytes32 get_storage(evmc::address addr, evmc::bytes32 key) const noexcept override {
        return state_.get_original_storage(addr, key);
    }

    evmc::bytes32 get_block_hash(int64_t n) const override {
        return evm_.get_block_hash(n);
    }
};

ExecutionProcessor::ExecutionProcessor(const Block& block, protocol::IRuleSet& rule_set, State& state,
                                       const ChainConfig& config)
    : state_{state}, rule_set_{rule_set}, evm_{block, state_, config} {
    evm_.beneficiary = rule_set.get_beneficiary(block.header);

    e1_block_ = {
        .number = static_cast<int64_t>(block.header.number),
        .timestamp = static_cast<int64_t>(block.header.timestamp),
        .gas_limit = static_cast<int64_t>(block.header.gas_limit),
        .coinbase = block.header.beneficiary,
        .difficulty = static_cast<int64_t>(block.header.difficulty),
        .prev_randao = block.header.difficulty == 0 ? block.header.prev_randao : intx::be::store<evmone::state::bytes32>(intx::uint256{block.header.difficulty}),
        .base_fee = static_cast<uint64_t>(block.header.base_fee_per_gas.value_or(0)),
        .excess_blob_gas = block.header.excess_blob_gas.value_or(0),
        .blob_base_fee = block.header.blob_gas_price().value_or(0),
    };
    // for (const auto& obh : block.ommers)
    //     e1_block_.ommers.emplace_back(obh.beneficiary, block.header.number - obh.number);
    // if (block.withdrawals) {
    //     for (const auto& w : *block.withdrawals)
    //         e1_block_.withdrawals.emplace_back(w.index, w.validator_index, w.address, w.amount);
    // }
    // const auto min_block_number = std::max(e1_block_.number - 257, int64_t{0});
    // for (auto n = min_block_number; n < e1_block_.number; ++n)
    //     e1_block_.known_block_hashes.insert({n, evm_.get_block_hash(n)});
}

void ExecutionProcessor::execute_transaction(const Transaction& txn, Receipt& receipt) noexcept {
    assert(protocol::validate_transaction(txn, state_, available_gas()) == ValidationResult::kOk);

    evmone::state::Transaction e1_tx{
        .type = static_cast<evmone::state::Transaction::Type>(txn.type),
        .data = txn.data,
        .gas_limit = static_cast<int64_t>(txn.gas_limit),
        .max_gas_price = txn.max_fee_per_gas,
        .max_priority_gas_price = txn.max_priority_fee_per_gas,
        .max_blob_gas_price = txn.max_fee_per_blob_gas,
        .sender = *txn.sender(),
        .to = txn.to,
        .value = txn.value,
        // access_list
        // blob_hashes
        .chain_id = static_cast<uint64_t>(txn.chain_id.value_or(0)),
        .nonce = txn.nonce};
    for (const auto& ae : txn.access_list)
        e1_tx.access_list.emplace_back(ae.account, ae.storage_keys);
    for (const auto& h : txn.blob_versioned_hashes)
        e1_tx.blob_hashes.emplace_back(static_cast<const evmc::bytes32&>(h));

    StateView sv{state_, evm_};

    const auto e1_receipt = evmone::state::transition(e1_ctx, sv, e1_block_, e1_tx, evm_.revision(), evm_.vm());
    const auto gas_used = static_cast<uint64_t>(e1_receipt.gas_used);

    // Optimization: since receipt.logs might have some capacity, let's reuse it.
    // std::swap(receipt.logs, state_.logs());

    // state_.clear_journal_and_substate();
    // auto snap = state_.take_snapshot();
    //
    // const std::optional<evmc::address> sender{txn.sender()};
    // assert(sender);
    // state_.access_account(*sender);
    //
    // if (txn.to) {
    //     state_.access_account(*txn.to);
    //     // EVM itself increments the nonce for contract creation
    //     state_.set_nonce(*sender, txn.nonce + 1);
    // }
    //
    // for (const AccessListEntry& ae : txn.access_list) {
    //     state_.access_account(ae.account);
    //     for (const evmc::bytes32& key : ae.storage_keys) {
    //         state_.access_storage(ae.account, key);
    //     }
    // }
    //
    // const evmc_revision rev{evm_.revision()};
    // if (rev >= EVMC_SHANGHAI) {
    //     // EIP-3651: Warm COINBASE
    //     state_.access_account(evm_.beneficiary);
    // }
    //
    // const BlockHeader& header{evm_.block().header};
    //
    // const intx::uint256 sender_initial_balance{state_.get_balance(*sender)};
    // const intx::uint256 recipient_initial_balance{state_.get_balance(evm_.beneficiary)};
    //
    // // EIP-1559 normal gas cost
    // const intx::uint256 base_fee_per_gas{header.base_fee_per_gas.value_or(0)};
    // const intx::uint256 effective_gas_price{txn.effective_gas_price(base_fee_per_gas)};
    // state_.subtract_from_balance(*sender, txn.gas_limit * effective_gas_price);
    //
    // // EIP-4844 blob gas cost (calc_data_fee)
    // const intx::uint256 blob_gas_price{header.blob_gas_price().value_or(0)};
    // state_.subtract_from_balance(*sender, txn.total_blob_gas() * blob_gas_price);
    //
    // const intx::uint128 g0{protocol::intrinsic_gas(txn, rev)};
    // assert(g0 <= UINT64_MAX);  // true due to the precondition (transaction must be valid)
    //
    // const CallResult vm_res{evm_.execute(txn, txn.gas_limit - static_cast<uint64_t>(g0))};
    //
    // refund_gas(txn, vm_res.gas_left, vm_res.gas_refund);
    //
    // // award the fee recipient
    // const intx::uint256 amount{txn.priority_fee_per_gas(base_fee_per_gas) * gas_used};
    // state_.add_to_balance(evm_.beneficiary, amount);
    //
    // if (rev >= EVMC_LONDON) {
    //     const evmc::address* burnt_contract{protocol::bor::config_value_lookup(evm_.config().burnt_contract,
    //                                                                            header.number)};
    //     if (burnt_contract) {
    //         const intx::uint256 would_be_burnt{gas_used * base_fee_per_gas};
    //         state_.add_to_balance(*burnt_contract, would_be_burnt);
    //     }
    // }
    //
    // rule_set_.add_fee_transfer_log(state_, amount, *sender, sender_initial_balance,
    //                                evm_.beneficiary, recipient_initial_balance);
    //
    // state_.finalize_transaction(rev);
    //
    // // Clean up the state.
    // state_.logs().clear();  // seems unnecessary

    cumulative_gas_used_ += gas_used;

    receipt.type = txn.type;
    receipt.success = e1_receipt.status == EVMC_SUCCESS;
    receipt.cumulative_gas_used = cumulative_gas_used_;
    receipt.logs.clear();  // can be dirty
    receipt.logs.reserve(e1_receipt.logs.size());
    for (auto& l : e1_receipt.logs)
        receipt.logs.push_back(Log{l.addr, l.topics, l.data});
    receipt.bloom = logs_bloom(receipt.logs);

    // if (static_cast<uint64_t>(e1_receipt.gas_used) != gas_used) {
    //     std::cerr << "g: " << e1_receipt.gas_used << ", silkworm: " << gas_used << "\n";
    //     SILKWORM_ASSERT(static_cast<uint64_t>(e1_receipt.gas_used) == gas_used);
    // }

    // SILKWORM_ASSERT(receipt.logs.size() == logs.size());
    // for (size_t i = 0; i < receipt.logs.size(); ++i) {
    //     const auto& e1l = logs[i];
    //     const auto& exp = receipt.logs[i];
    //     SILKWORM_ASSERT(e1l.address == exp.address);
    //     SILKWORM_ASSERT(e1l.topics.size() == exp.topics.size());
    //     for (size_t j = 0; j < exp.topics.size(); ++j) {
    //         SILKWORM_ASSERT(e1l.topics[j] == exp.topics[j]);
    //     }
    //     SILKWORM_ASSERT(e1l.data == exp.data);
    // }

    const auto& e1_state_diff = e1_receipt.state_diff;
    // for (const auto& [a, c] : e1_state_diff.modified_storage) {
    //     if (e1_state_diff.deleted_accounts.contains(a))
    //         continue;
    //
    //     for (const auto& [k, v] : c) {
    //         auto expected = state_.get_current_storage(a, k);
    //         if (v != expected) {
    //             std::cerr << "k: " << hex(k) << " e1: " << hex(v) << ", silkworm: " << hex(expected) << "\n";
    //             receipt.success = false;
    //             __builtin_trap();
    //         }
    //     }
    // }
    // for (const auto& a : e1_state_diff.deleted_accounts) {
    //     SILKWORM_ASSERT(!state_.exists(a));
    // }
    // for (const auto& [a, m] : e1_state_diff.modified_accounts) {
    //     if (e1_state_diff.deleted_accounts.contains(a))
    //         continue;
    //
    //     if (m.nonce) {
    //         SILKWORM_ASSERT(state_.get_nonce(a) == *m.nonce);
    //     }
    //     if (m.balance) {
    //         if (*m.balance != state_.get_balance(a)) {
    //             std::cerr << "b: " << hex(a) << " " << to_string(*m.balance) << ", silkworm: " << to_string(state_.get_balance(a)) << "\n";
    //             SILKWORM_ASSERT(state_.get_balance(a) == *m.balance);
    //         }
    //     }
    //     if (m.code) {
    //         SILKWORM_ASSERT(state_.get_code(a) == *m.code);
    //     }
    // }
    //
    // if (e1_receipt.status == EVMC_FAILURE) {  // imprecise error code
    //     SILKWORM_ASSERT(!receipt.success);
    // } else if (e1_receipt.status != EVMC_OUT_OF_GAS && vm_res.status != EVMC_PRECOMPILE_FAILURE) {
    //     if (e1_receipt.status != vm_res.status) {
    //         std::cerr << "e1: " << e1_receipt.status << ", silkworm: " << vm_res.status << "\n";
    //         receipt.success = !receipt.success;
    //     }
    //     //        SILKWORM_ASSERT(e1_receipt.status == vm_res.status);
    // }
    //
    // state_.revert_to_snapshot(snap);  // revert all what happened

    for (const auto& [a, m] : e1_state_diff.modified_accounts) {
        if (m.code) {
            state_.create_contract(a);  // bump incarnation?
            state_.set_code(a, *m.code);
        }

        auto& acc = state_.get_or_create_object(a);
        if (m.nonce) {
            acc.current->nonce = *m.nonce;
        }
        if (m.balance) {
            acc.current->balance = *m.balance;
        }
    }
    for (const auto& [a, s] : e1_state_diff.modified_storage) {
        auto& storage = state_.storage_[a];
        for (const auto& [k, v] : s) {
            storage.committed[k].original = v;
        }
    }
    for (const auto& a : e1_state_diff.deleted_accounts) {
        state_.destruct(a);
    }
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
    state_.add_to_balance(*txn.sender(), gas_left * effective_gas_price);

    return gas_left;
}

ValidationResult ExecutionProcessor::execute_block_no_post_validation(std::vector<Receipt>& receipts) noexcept {
    const evmc_revision rev{evm_.revision()};
    rule_set_.initialize(evm_);
    state_.finalize_transaction(rev);

    cumulative_gas_used_ = 0;

    const Block& block{evm_.block()};
    notify_block_execution_start(block);

    receipts.resize(block.transactions.size());
    auto receipt_it{receipts.begin()};
    for (const auto& txn : block.transactions) {
        const ValidationResult err{protocol::validate_transaction(txn, state_, available_gas())};
        if (err != ValidationResult::kOk) {
            return err;
        }
        execute_transaction(txn, *receipt_it);
        ++receipt_it;
    }

    rule_set_.finalize(state_, block);
    state_.finalize_transaction(rev);

    notify_block_execution_end(block);

    return ValidationResult::kOk;
}

ValidationResult ExecutionProcessor::execute_and_write_block(std::vector<Receipt>& receipts) noexcept {
    if (const ValidationResult res{execute_block_no_post_validation(receipts)}; res != ValidationResult::kOk) {
        return res;
    }

    const auto& header{evm_.block().header};

    if (cumulative_gas_used_ != header.gas_used) {
        return ValidationResult::kWrongBlockGas;
    }

    if (evm_.revision() >= EVMC_BYZANTIUM) {
        // Prior to Byzantium (EIP-658), receipts contained the root of the state after each individual transaction.
        // We don't calculate such intermediate state roots and thus can't verify the receipt root before Byzantium.
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

//! \brief Notify the registered tracers at the start of block execution.
void ExecutionProcessor::notify_block_execution_start(const Block& block) {
    for (auto& tracer : evm_.tracers()) {
        tracer.get().on_block_start(block);
    }
}

//! \brief Notify the registered tracers at the end of block execution.
void ExecutionProcessor::notify_block_execution_end(const Block& block) {
    for (auto& tracer : evm_.tracers()) {
        tracer.get().on_block_end(block);
    }
}

}  // namespace silkworm
