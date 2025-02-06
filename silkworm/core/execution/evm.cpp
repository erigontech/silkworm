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

#include "evm.hpp"

#include <algorithm>
#include <cstring>
#include <iterator>
#include <memory>
#include <utility>

#include <ethash/keccak.hpp>
#include <evmone/evmone.h>
#include <evmone/tracing.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/execution/precompile.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/types/address.hpp>

namespace silkworm {

class DelegatingTracer : public evmone::Tracer {
  public:
    explicit DelegatingTracer(EvmTracer& tracer, IntraBlockState& intra_block_state) noexcept
        : tracer_(tracer), intra_block_state_(intra_block_state) {}

  private:
    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override {
        tracer_.on_execution_start(rev, msg, code);
    }

    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height,
                              int64_t gas, const evmone::ExecutionState& state) noexcept override {
        tracer_.on_instruction_start(pc, stack_top, stack_height, gas, state, intra_block_state_);
    }

    void on_execution_end(const evmc_result& result) noexcept override {
        tracer_.on_execution_end(result, intra_block_state_);
    }

    friend class EVM;

    EvmTracer& tracer_;
    IntraBlockState& intra_block_state_;
};

#ifdef __wasm__
evmc::VM EVM::evm1_{evmc_create_evmone()};  // we cannot use SILKWORM_THREAD_LOCAL i.e. static in WASM (duplicate-decl-specifier)
#else
SILKWORM_THREAD_LOCAL evmc::VM EVM::evm1_{evmc_create_evmone()};
#endif  // __wasm__

EVM::EVM(const Block& block, IntraBlockState& state, const ChainConfig& config) noexcept
    : beneficiary{block.header.beneficiary},
      block_{block},
      state_{state},
      config_{config} {}

EVM::~EVM() {
    vm_impl().remove_tracers();
}

CallResult EVM::execute(const Transaction& txn, uint64_t gas) noexcept {
    SILKWORM_ASSERT(txn.sender());  // sender must be valid

    txn_ = &txn;

    const bool contract_creation{!txn.to.has_value()};
    const evmc::address destination{contract_creation ? evmc::address{} : *txn.to};

    const evmc_message message{
        .kind = contract_creation ? EVMC_CREATE : EVMC_CALL,
        .gas = static_cast<int64_t>(gas),
        .recipient = destination,
        .sender = *txn.sender(),
        .input_data = txn.data.data(),
        .input_size = txn.data.size(),
        .value = intx::be::store<evmc::uint256be>(txn.value),
        .code_address = destination,
    };

    evmc::Result res{contract_creation ? create(message) : call(message)};

    const auto gas_left = static_cast<uint64_t>(res.gas_left);
    const auto gas_refund = static_cast<uint64_t>(res.gas_refund);
    return {ValidationResult::kOk, res.status_code, gas_left, gas_refund, {res.output_data, res.output_size}};
}

evmc::Result EVM::create(const evmc_message& message) noexcept {
    evmc::Result res{EVMC_SUCCESS, message.gas, 0};

    auto value{intx::be::load<intx::uint256>(message.value)};
    const auto owned_funds = state_.get_balance(message.sender);
    if (!bailout && owned_funds < value) {
        res.status_code = EVMC_INSUFFICIENT_BALANCE;

        for (auto tracer : tracers_) {
            tracer.get().on_pre_check_failed(res.raw(), message);
        }

        return res;
    }

    const uint64_t nonce{state_.get_nonce(message.sender)};
    if (nonce + 1 < nonce) {
        // EIP-2681: Limit account nonce to 2^64-1
        // See also https://github.com/ethereum/go-ethereum/blob/v1.10.13/core/vm/evm.go#L426
        res.status_code = EVMC_ARGUMENT_OUT_OF_RANGE;

        for (auto tracer : tracers_) {
            tracer.get().on_pre_check_failed(res.raw(), message);
        }
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

    transfer(state_, message.sender, contract_addr, value, bailout);

    const evmc_message deploy_message{
        .kind = message.depth > 0 ? message.kind : EVMC_CALL,
        .depth = message.depth,
        .gas = message.gas,
        .gas_cost = message.gas_cost,
        .recipient = contract_addr,
        .sender = message.sender,
        .value = message.value,
        .create2_salt = message.create2_salt,
    };

    auto evm_res{execute(deploy_message, ByteView{message.input_data, message.input_size}, /*code_hash=*/nullptr)};

    if (evm_res.status_code == EVMC_SUCCESS) {
        const size_t code_len{evm_res.output_size};
        const uint64_t code_deploy_gas{code_len * protocol::fee::kGCodeDeposit};

        if (rev >= EVMC_SPURIOUS_DRAGON && code_len > protocol::kMaxCodeSize) {
            // EIP-170: Contract code size limit
            evm_res.status_code = EVMC_ARGUMENT_OUT_OF_RANGE;
        } else if (rev >= EVMC_LONDON && code_len > 0 && evm_res.output_data[0] == 0xEF) {
            // EIP-3541: Reject new contract code starting with the 0xEF byte
            evm_res.status_code = EVMC_CONTRACT_VALIDATION_FAILURE;
        } else if (std::cmp_greater_equal(evm_res.gas_left, code_deploy_gas)) {
            evm_res.gas_left -= static_cast<int64_t>(code_deploy_gas);
            state_.set_code(contract_addr, {evm_res.output_data, evm_res.output_size});
        } else if (rev >= EVMC_HOMESTEAD) {
            evm_res.status_code = EVMC_OUT_OF_GAS;
        }
    }

    if (evm_res.status_code == EVMC_SUCCESS) {
        evm_res.create_address = contract_addr;
    } else {
        state_.revert_to_snapshot(snapshot);
        evm_res.gas_refund = 0;
        if (evm_res.status_code != EVMC_REVERT) {
            evm_res.gas_left = 0;
        }
    }

    // Explicitly notify registered tracers (if any) because evmc_result has been changed post execute
    for (auto tracer : tracers_) {
        tracer.get().on_creation_completed(evm_res, state_);
    }

    return evmc::Result{evm_res};
}

evmc::Result EVM::call(const evmc_message& message) noexcept {
    evmc::Result res{EVMC_SUCCESS, message.gas};

    const auto value{intx::be::load<intx::uint256>(message.value)};
    const auto owned_funds = state_.get_balance(message.sender);
    if (!bailout && message.kind != EVMC_DELEGATECALL && owned_funds < value) {
        res.status_code = EVMC_INSUFFICIENT_BALANCE;
        return res;
    }

    const auto snapshot{state_.take_snapshot()};

    if (message.kind == EVMC_CALL) {
        if (message.flags & EVMC_STATIC) {
            // Match geth logic
            // https://github.com/ethereum/go-ethereum/blob/v1.9.25/core/vm/evm.go#L391
            state_.touch(message.recipient);
        } else {
            transfer(state_, message.sender, message.recipient, value, bailout);
        }
    }

    const evmc_revision rev{revision()};

    if (precompile::is_precompile(message.code_address, rev)) {
        static_assert(std::size(precompile::kContracts) < 256);
        const uint8_t num{message.code_address.bytes[kAddressLength - 1]};
        const precompile::Contract& contract{precompile::kContracts[num]->contract};
        const ByteView input{message.input_data, message.input_size};
        const uint64_t gas{contract.gas(input, rev)};
        if (std::cmp_greater(gas, message.gas)) {
            res.status_code = EVMC_OUT_OF_GAS;
        } else {
            const std::optional<Bytes> output{contract.run(input)};
            if (output) {
                res = evmc::Result{EVMC_SUCCESS, message.gas - static_cast<int64_t>(gas), 0, message.gas_cost,
                                   output->data(), output->size()};
            } else {
                res.status_code = EVMC_PRECOMPILE_FAILURE;
            }
        }
        // Explicitly notify registered tracers (if any)
        for (auto tracer : tracers_) {
            const ByteView empty_code{};  // Any precompile code is empty
            tracer.get().on_execution_start(rev, message, empty_code);
            tracer.get().on_precompiled_run(res.raw(), state_);
            tracer.get().on_execution_end(res.raw(), state_);
        }
    } else {
        const ByteView code{state_.get_code(message.code_address)};
        if (code.empty() && tracers_.empty()) {  // Do not skip execution if there are any tracers
            return res;
        }

        const evmc::bytes32 code_hash{state_.get_code_hash(message.code_address)};
        res = evmc::Result{execute(message, code, &code_hash)};
    }

    if (res.status_code != EVMC_SUCCESS) {
        state_.revert_to_snapshot(snapshot);
        res.gas_refund = 0;
        if (res.status_code != EVMC_REVERT) {
            res.gas_left = 0;
        }
    }

    return res;
}

evmc_result EVM::execute(const evmc_message& message, ByteView code, const evmc::bytes32* code_hash) noexcept {
    const evmc_revision rev{revision()};
    if (exo_evm) {
        EvmHost host{*this};
        return exo_evm->execute(exo_evm, &EvmHost::get_interface(), host.to_context(), rev, &message,
                                code.data(), code.size());
    }
    return execute_with_baseline_interpreter(rev, message, code, code_hash);
}

evmc_result EVM::execute_with_baseline_interpreter(evmc_revision rev, const evmc_message& message, ByteView code,
                                                   const evmc::bytes32* code_hash) noexcept {
    std::shared_ptr<evmone::baseline::CodeAnalysis> analysis;
    const bool use_cache{code_hash && analysis_cache};
    if (use_cache) {
        const auto optional_analysis{analysis_cache->get_as_copy(*code_hash)};
        if (optional_analysis) {
            analysis = *optional_analysis;
        }
    }
    if (!analysis) {
        // EOF is disabled although evmone supports it. This will be needed as early as Prague, maybe later.
        analysis = std::make_shared<evmone::baseline::CodeAnalysis>(evmone::baseline::analyze(code, /*eof_enabled=*/false));
        if (use_cache) {
            analysis_cache->put(*code_hash, analysis);
        }
    }

    EvmHost host{*this};
    evmc_result res{evmone::baseline::execute(vm_impl(), EvmHost::get_interface(), host.to_context(), rev, message, *analysis)};
    return res;
}

evmc_revision EVM::revision() const noexcept {
    return config().revision(block_.header.number, block_.header.timestamp);
}

void EVM::add_tracer(EvmTracer& tracer) noexcept {
    vm_impl().add_tracer(std::make_unique<DelegatingTracer>(tracer, state_));
    tracers_.push_back(std::ref(tracer));
}

void EVM::remove_tracers() noexcept {
    vm_impl().remove_tracers();
    tracers_.clear();
}

bool EvmHost::account_exists(const evmc::address& address) const noexcept {
    const evmc_revision rev{evm_.revision()};
    if (rev >= EVMC_SPURIOUS_DRAGON) {
        return !evm_.state().is_dead(address);
    }
    return evm_.state().exists(address);
}

evmc_access_status EvmHost::access_account(const evmc::address& address) noexcept {
    const evmc_revision rev{evm_.revision()};

    if (precompile::is_precompile(address, rev)) {
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
                                         const evmc::bytes32& value) noexcept {
    const evmc::bytes32 current_val{evm_.state().get_current_storage(address, key)};

    if (current_val == value) {
        return EVMC_STORAGE_ASSIGNED;
    }

    evm_.state().set_storage(address, key, value);

    // https://eips.ethereum.org/EIPS/eip-1283
    const evmc::bytes32 original_val{evm_.state().get_original_storage(address, key)};

    if (original_val == current_val) {
        if (is_zero(original_val)) {
            return EVMC_STORAGE_ADDED;
        }
        // !is_zero(original_val)
        if (is_zero(value)) {
            return EVMC_STORAGE_DELETED;
        }
        return EVMC_STORAGE_MODIFIED;
    }
    // original_val != current_val
    if (!is_zero(original_val)) {
        if (is_zero(current_val)) {
            if (original_val == value) {
                return EVMC_STORAGE_DELETED_RESTORED;
            }
            return EVMC_STORAGE_DELETED_ADDED;
        }
        // !is_zero(current_val)
        if (is_zero(value)) {
            return EVMC_STORAGE_MODIFIED_DELETED;
        }
        // !is_zero(value)
        if (original_val == value) {
            return EVMC_STORAGE_MODIFIED_RESTORED;
        }
        return EVMC_STORAGE_ASSIGNED;
    }
    // is_zero(original_val)
    if (original_val == value) {
        return EVMC_STORAGE_ADDED_DELETED;
    }
    return EVMC_STORAGE_ASSIGNED;
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
    }
    return evm_.state().get_code_hash(address);
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

bool EvmHost::selfdestruct(const evmc::address& address, const evmc::address& beneficiary) noexcept {
    const intx::uint256 balance{evm_.state().get_balance(address)};
    evm_.state().add_to_balance(beneficiary, balance);
    bool recorded{false};
    if (evm_.revision() >= EVMC_CANCUN && !evm_.state().created().contains(address)) {
        evm_.state().subtract_from_balance(address, balance);
    } else {
        evm_.state().set_balance(address, 0);
        recorded = evm_.state().record_suicide(address);
    }
    for (auto tracer : evm_.tracers()) {
        tracer.get().on_self_destruct(address, beneficiary);
    }
    return recorded;
}

evmc::Result EvmHost::call(const evmc_message& message) noexcept {
    if (message.kind == EVMC_CREATE || message.kind == EVMC_CREATE2) {
        evmc::Result res{evm_.create(message)};

        // https://eips.ethereum.org/EIPS/eip-211
        if (res.status_code == EVMC_REVERT) {
            // geth returns CREATE output only in case of REVERT
            return res;
        }
        evmc::Result res_with_no_output{res.status_code, res.gas_left, res.gas_refund};
        res_with_no_output.create_address = res.create_address;
        return res_with_no_output;
    }
    return evm_.call(message);
}

evmc_tx_context EvmHost::get_tx_context() const noexcept {
    const BlockHeader& header{evm_.block_.header};
    evmc_tx_context context{};
    const intx::uint256 base_fee_per_gas{header.base_fee_per_gas.value_or(0)};
    const intx::uint256 effective_gas_price{evm_.txn_->effective_gas_price(base_fee_per_gas)};
    intx::be::store(context.tx_gas_price.bytes, effective_gas_price);
    context.tx_origin = *evm_.txn_->sender();
    context.block_coinbase = evm_.beneficiary;
    SILKWORM_ASSERT(header.number <= INT64_MAX);  // EIP-1985
    context.block_number = static_cast<int64_t>(header.number);
    context.block_timestamp = static_cast<int64_t>(header.timestamp);
    SILKWORM_ASSERT(header.gas_limit <= INT64_MAX);  // EIP-1985
    context.block_gas_limit = static_cast<int64_t>(header.gas_limit);
    if (header.difficulty == 0) {
        // EIP-4399: Supplant DIFFICULTY opcode with RANDOM
        // We use 0 header difficulty as the telltale of PoS blocks
        std::memcpy(context.block_prev_randao.bytes, header.prev_randao.bytes, kHashLength);
    } else {
        intx::be::store(context.block_prev_randao.bytes, header.difficulty);
    }
    intx::be::store(context.chain_id.bytes, intx::uint256{evm_.config().chain_id});
    intx::be::store(context.block_base_fee.bytes, base_fee_per_gas);
    const intx::uint256 blob_gas_price{header.blob_gas_price().value_or(0)};
    intx::be::store(context.blob_base_fee.bytes, blob_gas_price);
    context.blob_hashes = evm_.txn_->blob_versioned_hashes.data();
    context.blob_hashes_count = evm_.txn_->blob_versioned_hashes.size();
    return context;
}

evmc::bytes32 EVM::get_block_hash(int64_t block_num) noexcept {
    SILKWORM_ASSERT(block_num >= 0);
    const uint64_t current_block_num{block_.header.number};
    SILKWORM_ASSERT(static_cast<uint64_t>(block_num) < current_block_num);
    const uint64_t new_size_u64{current_block_num - static_cast<uint64_t>(block_num)};
    SILKWORM_ASSERT(std::in_range<size_t>(new_size_u64));
    const size_t new_size{static_cast<size_t>(new_size_u64)};

    std::vector<evmc::bytes32>& hashes{block_hashes_};
    if (hashes.empty()) {
        hashes.push_back(block_.header.parent_hash);
    }

    const size_t old_size{hashes.size()};
    if (old_size < new_size) {
        hashes.resize(new_size);
    }

    for (size_t i{old_size}; i < new_size; ++i) {
        std::optional<BlockHeader> header{state().db().read_header(current_block_num - i, hashes[i - 1])};
        if (!header) {
            break;
        }
        hashes[i] = header->parent_hash;
    }

    return hashes[new_size - 1];
}

evmc::bytes32 EvmHost::get_block_hash(int64_t block_num) const noexcept {
    return evm_.get_block_hash(block_num);
}

void EvmHost::emit_log(const evmc::address& address, const uint8_t* data, size_t data_size,
                       const evmc::bytes32 topics[], size_t num_topics) noexcept {
    Log log{address};
    std::copy_n(topics, num_topics, std::back_inserter(log.topics));
    std::copy_n(data, data_size, std::back_inserter(log.data));
    evm_.state().add_log(log);
}

evmc::bytes32 EvmHost::get_transient_storage(const evmc::address& addr, const evmc::bytes32& key) const noexcept {
    return evm_.state().get_transient_storage(addr, key);
}

void EvmHost::set_transient_storage(const evmc::address& addr, const evmc::bytes32& key, const evmc::bytes32& value) noexcept {
    evm_.state().set_transient_storage(addr, key, value);
}

}  // namespace silkworm
