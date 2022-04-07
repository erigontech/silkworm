/*
   Copyright 2020-2022 The Silkworm Authors

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

#include <algorithm>
#include <cassert>
#include <cstring>
#include <iterator>
#include <memory>

#include <ethash/keccak.hpp>
#include <evmone/advanced_execution.hpp>
#include <evmone/evmone.h>
#include <evmone/tracing.hpp>
#include <evmone/vm.hpp>
#include <silkpre/precompile.h>

#include <silkworm/chain/protocol_param.hpp>

#include "address.hpp"

namespace silkworm {

class DelegatingTracer : public evmone::Tracer {
  public:
    explicit DelegatingTracer(EvmTracer& tracer, IntraBlockState& intra_block_state) noexcept
        : tracer_(tracer), intra_block_state_(intra_block_state) {}

  private:
    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override {
        tracer_.on_execution_start(rev, msg, code);
    }

    void on_instruction_start(uint32_t pc, const intx::uint256*, int,
                              const evmone::ExecutionState& state) noexcept override {
        tracer_.on_instruction_start(pc, state, intra_block_state_);
    }

    void on_execution_end(const evmc_result& result) noexcept override {
        tracer_.on_execution_end(result, intra_block_state_);
    }

    friend class EVM;

    EvmTracer& tracer_;
    IntraBlockState& intra_block_state_;
};

EVM::EVM(const Block& block, IntraBlockState& state, const ChainConfig& config) noexcept
    : beneficiary{block.header.beneficiary},
      block_{block},
      state_{state},
      config_{config},
      evm1_{evmc_create_evmone()} {}

EVM::~EVM() { evm1_->destroy(evm1_); }

CallResult EVM::execute(const Transaction& txn, uint64_t gas) noexcept {
    assert(txn.from.has_value());  // sender must be recovered

    txn_ = &txn;

    const bool contract_creation{!txn.to.has_value()};
    const evmc::address destination{contract_creation ? evmc::address{} : *txn.to};

    evmc_message message{
        contract_creation ? EVMC_CREATE : EVMC_CALL,  // kind
        0,                                            // flags
        0,                                            // depth
        static_cast<int64_t>(gas),                    // gas
        destination,                                  // recipient
        *txn.from,                                    // sender
        &txn.data[0],                                 // input_data
        txn.data.size(),                              // input_size
        intx::be::store<evmc::uint256be>(txn.value),  // value
        {},                                           // create2_salt
        destination,                                  // code_address
    };

    evmc::result res{contract_creation ? create(message) : call(message)};

    return {res.status_code, static_cast<uint64_t>(res.gas_left), {res.output_data, res.output_size}};
}

evmc::result EVM::create(const evmc_message& message) noexcept {
    evmc::result res{EVMC_SUCCESS, message.gas, nullptr, 0};

    auto value{intx::be::load<intx::uint256>(message.value)};
    if (state_.get_balance(message.sender) < value) {
        res.status_code = EVMC_INSUFFICIENT_BALANCE;
        return res;
    }

    const uint64_t nonce{state_.get_nonce(message.sender)};
    if (nonce + 1 < nonce) {
        // EIP-2681: Limit account nonce to 2^64-1
        // See also https://github.com/ethereum/go-ethereum/blob/v1.10.13/core/vm/evm.go#L426
        res.status_code = EVMC_ARGUMENT_OUT_OF_RANGE;
        return res;
    }
    state_.set_nonce(message.sender, nonce + 1);

    evmc::address contract_addr{};
    if (message.kind == EVMC_CREATE) {
        contract_addr = create_address(message.sender, nonce);
    } else if (message.kind == EVMC_CREATE2) {
        auto init_code_hash{ethash::keccak256(message.input_data, message.input_size)};
        contract_addr = create2_address(message.sender, message.create2_salt, init_code_hash.bytes);
    }

    state_.access_account(contract_addr);

    if (state_.get_nonce(contract_addr) != 0 || state_.get_code_hash(contract_addr) != kEmptyHash) {
        // https://github.com/ethereum/EIPs/issues/684
        res.status_code = EVMC_INVALID_INSTRUCTION;
        res.gas_left = 0;
        return res;
    }

    auto snapshot{state_.take_snapshot()};

    state_.create_contract(contract_addr);

    const evmc_revision rev{revision()};
    if (rev >= EVMC_SPURIOUS_DRAGON) {
        state_.set_nonce(contract_addr, 1);
    }

    state_.subtract_from_balance(message.sender, value);
    state_.add_to_balance(contract_addr, value);

    const evmc_message deploy_message{
        EVMC_CALL,       // kind
        0,               // flags
        message.depth,   // depth
        message.gas,     // gas
        contract_addr,   // recipient
        message.sender,  // sender
        nullptr,         // input_data
        0,               // input_size
        message.value,   // value
    };

    res =
        evmc::result{execute(deploy_message, ByteView{message.input_data, message.input_size}, /*code_hash=*/nullptr)};

    if (res.status_code == EVMC_SUCCESS) {
        const size_t code_len{res.output_size};
        const uint64_t code_deploy_gas{code_len * fee::kGCodeDeposit};

        if (rev >= EVMC_LONDON && code_len > 0 && res.output_data[0] == 0xEF) {
            // https://eips.ethereum.org/EIPS/eip-3541
            res.status_code = EVMC_CONTRACT_VALIDATION_FAILURE;
        } else if (rev >= EVMC_SPURIOUS_DRAGON && code_len > param::kMaxCodeSize) {
            // https://eips.ethereum.org/EIPS/eip-170
            res.status_code = EVMC_OUT_OF_GAS;
        } else if (res.gas_left >= 0 && static_cast<uint64_t>(res.gas_left) >= code_deploy_gas) {
            res.gas_left -= static_cast<int64_t>(code_deploy_gas);
            state_.set_code(contract_addr, {res.output_data, res.output_size});
        } else if (rev >= EVMC_HOMESTEAD) {
            res.status_code = EVMC_OUT_OF_GAS;
        }
    }

    if (res.status_code == EVMC_SUCCESS) {
        res.create_address = contract_addr;
    } else {
        state_.revert_to_snapshot(snapshot);
        if (res.status_code != EVMC_REVERT) {
            res.gas_left = 0;
        }
    }

    return res;
}

evmc::result EVM::call(const evmc_message& message) noexcept {
    evmc_result res{evmc_make_result(EVMC_SUCCESS, message.gas, nullptr, 0)};

    const auto value{intx::be::load<intx::uint256>(message.value)};
    if (message.kind != EVMC_DELEGATECALL && state_.get_balance(message.sender) < value) {
        res.status_code = EVMC_INSUFFICIENT_BALANCE;
        return evmc::result{res};
    }

    const bool precompiled{is_precompiled(message.code_address)};
    const evmc_revision rev{revision()};

    // https://eips.ethereum.org/EIPS/eip-161
    if (value == 0 && rev >= EVMC_SPURIOUS_DRAGON && !precompiled && !state_.exists(message.code_address)) {
        return evmc::result{res};
    }

    const auto snapshot{state_.take_snapshot()};

    if (message.kind == EVMC_CALL) {
        if (message.flags & EVMC_STATIC) {
            // Match geth logic
            // https://github.com/ethereum/go-ethereum/blob/v1.9.25/core/vm/evm.go#L391
            state_.touch(message.recipient);
        } else {
            state_.subtract_from_balance(message.sender, value);
            state_.add_to_balance(message.recipient, value);
        }
    }

    if (precompiled) {
        const uint8_t num{message.code_address.bytes[kAddressLength - 1]};
        SilkpreContract contract{kSilkpreContracts[num - 1]};
        const ByteView input{message.input_data, message.input_size};
        const int64_t gas{static_cast<int64_t>(contract.gas(input.data(), input.length(), revision()))};
        if (gas < 0 || gas > message.gas) {
            res.status_code = EVMC_OUT_OF_GAS;
        } else {
            SilkpreOutput output{contract.run(input.data(), input.length())};
            if (output.data) {
                res.gas_left -= gas;
                res.output_size = output.size;
                res.output_data = output.data;
                res.release = evmc_free_result_memory;
            } else {
                res.status_code = EVMC_PRECOMPILE_FAILURE;
            }
        }
    } else {
        const ByteView code{state_.get_code(message.code_address)};
        if (code.empty()) {
            return evmc::result{res};
        }

        const evmc::bytes32 code_hash{state_.get_code_hash(message.code_address)};
        res = execute(message, code, &code_hash);
    }

    if (res.status_code != EVMC_SUCCESS) {
        state_.revert_to_snapshot(snapshot);
        if (res.status_code != EVMC_REVERT) {
            res.gas_left = 0;
        }
    }

    return evmc::result{res};
}

evmc_result EVM::execute(const evmc_message& msg, ByteView code, const evmc::bytes32* code_hash) noexcept {
    const evmc_revision rev{revision()};

    if (exo_evm) {
        EvmHost host{*this};
        return exo_evm->execute(exo_evm, &host.get_interface(), host.to_context(), rev, &msg, code.data(), code.size());
    } else if (code_hash && advanced_analysis_cache) {
        return execute_with_advanced_interpreter(rev, msg, code, *code_hash);
    } else {
        // for one-off execution baseline interpreter is generally faster
        return execute_with_baseline_interpreter(rev, msg, code, code_hash);
    }
}

gsl::owner<EvmoneExecutionState*> EVM::acquire_state() noexcept {
    gsl::owner<EvmoneExecutionState*> state{nullptr};
    if (state_pool) {
        state = state_pool->acquire();
    }
    if (!state) {
        state = new EvmoneExecutionState;
    }
    return state;
}

void EVM::release_state(gsl::owner<EvmoneExecutionState*> state) noexcept {
    if (state_pool) {
        state_pool->add(state);
    } else {
        delete state;
    }
}

evmc_result EVM::execute_with_baseline_interpreter(evmc_revision rev, const evmc_message& msg, ByteView code,
                                                   const evmc::bytes32* code_hash) noexcept {
    std::shared_ptr<evmone::baseline::CodeAnalysis> analysis;
    const bool use_cache{code_hash && baseline_analysis_cache};
    if (use_cache) {
        const auto* ptr{baseline_analysis_cache->get(*code_hash)};
        if (ptr) {
            analysis = *ptr;
        }
    }
    if (!analysis) {
        analysis = std::make_shared<evmone::baseline::CodeAnalysis>(evmone::baseline::analyze(code));
        if (use_cache) {
            baseline_analysis_cache->put(*code_hash, analysis);
        }
    }

    EvmHost host{*this};
    gsl::owner<EvmoneExecutionState*> state{acquire_state()};
    state->reset(msg, rev, host.get_interface(), host.to_context(), code);

    const auto vm{static_cast<evmone::VM*>(evm1_)};
    evmc_result res{evmone::baseline::execute(*vm, *state, *analysis)};

    release_state(state);

    return res;
}

evmc_result EVM::execute_with_advanced_interpreter(evmc_revision rev, const evmc_message& msg, ByteView code,
                                                   const evmc::bytes32& code_hash) noexcept {
    assert(advanced_analysis_cache != nullptr);

    std::shared_ptr<evmone::advanced::AdvancedCodeAnalysis> analysis{advanced_analysis_cache->get(code_hash, rev)};
    if (!analysis) {
        analysis = std::make_shared<evmone::advanced::AdvancedCodeAnalysis>(evmone::advanced::analyze(rev, code));
        advanced_analysis_cache->put(code_hash, analysis, rev);
    }

    EvmHost host{*this};
    gsl::owner<EvmoneExecutionState*> state{acquire_state()};
    state->reset(msg, rev, host.get_interface(), host.to_context(), code);

    evmc_result res{evmone::advanced::execute(*state, *analysis)};

    release_state(state);

    return res;
}

evmc_revision EVM::revision() const noexcept { return config().revision(block_.header.number); }

void EVM::add_tracer(EvmTracer& tracer) noexcept {
    assert(advanced_analysis_cache == nullptr);

    const auto vm{static_cast<evmone::VM*>(evm1_)};
    vm->add_tracer(std::make_unique<DelegatingTracer>(tracer, state_));
}

uint8_t EVM::number_of_precompiles() const noexcept {
    const evmc_revision rev{revision()};

    if (rev >= EVMC_ISTANBUL) {
        return SILKPRE_NUMBER_OF_ISTANBUL_CONTRACTS;
    } else if (rev >= EVMC_BYZANTIUM) {
        return SILKPRE_NUMBER_OF_BYZANTIUM_CONTRACTS;
    } else {
        return SILKPRE_NUMBER_OF_FRONTIER_CONTRACTS;
    }
}

bool EVM::is_precompiled(const evmc::address& contract) const noexcept {
    if (is_zero(contract)) {
        return false;
    }
    evmc::address max_precompiled{};
    max_precompiled.bytes[kAddressLength - 1] = number_of_precompiles();
    return contract <= max_precompiled;
}

bool EvmHost::account_exists(const evmc::address& address) const noexcept {
    const evmc_revision rev{evm_.revision()};

    if (rev >= EVMC_SPURIOUS_DRAGON) {
        return !evm_.state().is_dead(address);
    } else {
        return evm_.state().exists(address);
    }
}

evmc_access_status EvmHost::access_account(const evmc::address& address) noexcept {
    if (evm_.is_precompiled(address)) {
        return EVMC_ACCESS_WARM;
    }
    return evm_.state().access_account(address);
}

evmc_access_status EvmHost::access_storage(const evmc::address& address, const evmc::bytes32& key) noexcept {
    return evm_.state().access_storage(address, key);
}

evmc::bytes32 EvmHost::get_storage(const evmc::address& address, const evmc::bytes32& key) const noexcept {
    return evm_.state().get_current_storage(address, key);
}

evmc_storage_status EvmHost::set_storage(const evmc::address& address, const evmc::bytes32& key,
                                         const evmc::bytes32& new_val) noexcept {
    const evmc::bytes32 current_val{evm_.state().get_current_storage(address, key)};

    if (current_val == new_val) {
        return EVMC_STORAGE_UNCHANGED;
    }

    evm_.state().set_storage(address, key, new_val);

    const evmc_revision rev{evm_.revision()};
    const bool eip1283{rev >= EVMC_ISTANBUL || rev == EVMC_CONSTANTINOPLE};

    if (!eip1283) {
        if (is_zero(current_val)) {
            return EVMC_STORAGE_ADDED;
        }

        if (is_zero(new_val)) {
            evm_.state().add_refund(fee::kRSClear);
            return EVMC_STORAGE_DELETED;
        }

        return EVMC_STORAGE_MODIFIED;
    }

    const uint64_t sload_cost{[rev]() {
        if (rev >= EVMC_BERLIN) {
            return fee::kWarmStorageReadCost;
        } else if (rev >= EVMC_ISTANBUL) {
            return fee::kGSLoadIstanbul;
        } else {
            return fee::kGSLoadTangerineWhistle;
        }
    }()};

    uint64_t sstore_reset_gas{fee::kGSReset};
    if (rev >= EVMC_BERLIN) {
        sstore_reset_gas -= fee::kColdSloadCost;
    }

    // https://eips.ethereum.org/EIPS/eip-1283
    const evmc::bytes32 original_val{evm_.state().get_original_storage(address, key)};

    // https://eips.ethereum.org/EIPS/eip-3529
    const uint64_t sstore_clears_refund{rev >= EVMC_LONDON ? sstore_reset_gas + fee::kAccessListStorageKeyCost
                                                           : fee::kRSClear};

    if (original_val == current_val) {
        if (is_zero(original_val)) {
            return EVMC_STORAGE_ADDED;
        }
        if (is_zero(new_val)) {
            evm_.state().add_refund(sstore_clears_refund);
        }
        return EVMC_STORAGE_MODIFIED;
    } else {
        if (!is_zero(original_val)) {
            if (is_zero(current_val)) {
                evm_.state().subtract_refund(sstore_clears_refund);
            }
            if (is_zero(new_val)) {
                evm_.state().add_refund(sstore_clears_refund);
            }
        }
        if (original_val == new_val) {
            if (is_zero(original_val)) {
                evm_.state().add_refund(fee::kGSSet - sload_cost);
            } else {
                evm_.state().add_refund(sstore_reset_gas - sload_cost);
            }
        }
        return EVMC_STORAGE_MODIFIED_AGAIN;
    }
}

evmc::uint256be EvmHost::get_balance(const evmc::address& address) const noexcept {
    intx::uint256 balance{evm_.state().get_balance(address)};
    return intx::be::store<evmc::uint256be>(balance);
}

size_t EvmHost::get_code_size(const evmc::address& address) const noexcept {
    return evm_.state().get_code(address).size();
}

evmc::bytes32 EvmHost::get_code_hash(const evmc::address& address) const noexcept {
    if (evm_.state().is_dead(address)) {
        return {};
    } else {
        return evm_.state().get_code_hash(address);
    }
}

size_t EvmHost::copy_code(const evmc::address& address, size_t code_offset, uint8_t* buffer_data,
                          size_t buffer_size) const noexcept {
    ByteView code{evm_.state().get_code(address)};

    if (code_offset >= code.size()) {
        return 0;
    }

    size_t n{std::min(buffer_size, code.size() - code_offset)};
    std::copy_n(&code[code_offset], n, buffer_data);
    return n;
}

void EvmHost::selfdestruct(const evmc::address& address, const evmc::address& beneficiary) noexcept {
    evm_.state().record_suicide(address);
    evm_.state().add_to_balance(beneficiary, evm_.state().get_balance(address));
    evm_.state().set_balance(address, 0);
}

evmc::result EvmHost::call(const evmc_message& message) noexcept {
    if (message.kind == EVMC_CREATE || message.kind == EVMC_CREATE2) {
        evmc::result res{evm_.create(message)};

        // https://eips.ethereum.org/EIPS/eip-211
        if (res.status_code == EVMC_REVERT) {
            // geth returns CREATE output only in case of REVERT
            return res;
        } else {
            evmc::result res_with_no_output{res.status_code, res.gas_left, nullptr, 0};
            res_with_no_output.create_address = res.create_address;
            return res_with_no_output;
        }
    } else {
        return evm_.call(message);
    }
}

evmc_tx_context EvmHost::get_tx_context() const noexcept {
    const BlockHeader& header{evm_.block_.header};
    evmc_tx_context context;
    const intx::uint256 base_fee_per_gas{header.base_fee_per_gas.value_or(0)};
    const intx::uint256 effective_gas_price{evm_.txn_->effective_gas_price(base_fee_per_gas)};
    intx::be::store(context.tx_gas_price.bytes, effective_gas_price);
    context.tx_origin = *evm_.txn_->from;
    context.block_coinbase = evm_.beneficiary;
    assert(header.number <= INT64_MAX);  // EIP-1985
    context.block_number = static_cast<int64_t>(header.number);
    assert(header.timestamp <= INT64_MAX);  // EIP-1985
    context.block_timestamp = static_cast<int64_t>(header.timestamp);
    assert(header.gas_limit <= INT64_MAX);  // EIP-1985
    context.block_gas_limit = static_cast<int64_t>(header.gas_limit);
    if (header.difficulty != 0) {
        intx::be::store(context.block_difficulty.bytes, header.difficulty);
    } else {
        // EIP-4399: Supplant DIFFICULTY opcode with RANDOM
        // We use 0 header difficulty as the telltale of PoS blocks
        std::memcpy(context.block_difficulty.bytes, header.mix_hash.bytes, kHashLength);
    }
    intx::be::store(context.chain_id.bytes, intx::uint256{evm_.config().chain_id});
    intx::be::store(context.block_base_fee.bytes, base_fee_per_gas);
    return context;
}

evmc::bytes32 EvmHost::get_block_hash(int64_t n) const noexcept {
    const uint64_t base_number{evm_.block_.header.number};
    const uint64_t new_size{base_number - static_cast<uint64_t>(n)};
    assert(new_size <= 256);

    std::vector<evmc::bytes32>& hashes{evm_.block_hashes_};
    if (hashes.empty()) {
        hashes.push_back(evm_.block_.header.parent_hash);
    }

    const uint64_t old_size{hashes.size()};
    if (old_size < new_size) {
        hashes.resize(new_size);
    }

    for (uint64_t i{old_size}; i < new_size; ++i) {
        std::optional<BlockHeader> header{evm_.state().db().read_header(base_number - i, hashes[i - 1])};
        if (!header) {
            break;
        }
        hashes[i] = header->parent_hash;
    }

    return hashes[new_size - 1];
}

void EvmHost::emit_log(const evmc::address& address, const uint8_t* data, size_t data_size,
                       const evmc::bytes32 topics[], size_t num_topics) noexcept {
    Log log{address};
    std::copy_n(topics, num_topics, std::back_inserter(log.topics));
    std::copy_n(data, data_size, std::back_inserter(log.data));
    evm_.state().add_log(log);
}

}  // namespace silkworm
