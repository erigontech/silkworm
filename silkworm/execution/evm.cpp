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

#include "evm.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <ethash/keccak.hpp>
#include <iterator>

#include "address.hpp"
#include "analysis.hpp"
#include "analysis_cache.hpp"
#include "execution.hpp"
#include "precompiled.hpp"
#include "protocol_param.hpp"
#include "state_pool.hpp"

namespace silkworm {

EVM::EVM(const Block& block, IntraBlockState& state, const ChainConfig& config) noexcept
    : block_{block}, state_{state}, config_{config} {}

CallResult EVM::execute(const Transaction& txn, uint64_t gas) noexcept {
    txn_ = &txn;

    bool contract_creation{!txn.to};

    evmc_message message{
        contract_creation ? EVMC_CREATE : EVMC_CALL,  // kind
        0,                                            // flags
        0,                                            // depth
        static_cast<int64_t>(gas),                    // gas
        txn.to ? *txn.to : evmc::address{},           // destination
        *txn.from,                                    // sender
        &txn.data[0],                                 // input_data
        txn.data.size(),                              // input_size
        intx::be::store<evmc::uint256be>(txn.value),  // value
    };

    evmc::result res{contract_creation ? create(message) : call(message)};

    return {res.status_code, static_cast<uint64_t>(res.gas_left)};
}

evmc::result EVM::create(const evmc_message& message) noexcept {
    evmc::result res{EVMC_SUCCESS, message.gas, nullptr, 0};

    auto value{intx::be::load<intx::uint256>(message.value)};
    if (state_.get_balance(message.sender) < value) {
        res.status_code = static_cast<evmc_status_code>(EVMC_BALANCE_TOO_LOW);
        return res;
    }

    uint64_t nonce{state_.get_nonce(message.sender)};

    evmc::address contract_addr{};
    if (message.kind == EVMC_CREATE) {
        contract_addr = create_address(message.sender, nonce);
    } else if (message.kind == EVMC_CREATE2) {
        auto init_code_hash{ethash::keccak256(message.input_data, message.input_size)};
        contract_addr = create2_address(message.sender, message.create2_salt, init_code_hash.bytes);
    }

    state_.set_nonce(message.sender, nonce + 1);

    if (state_.get_nonce(contract_addr) != 0 || state_.get_code_hash(contract_addr) != kEmptyHash) {
        // https://github.com/ethereum/EIPs/issues/684
        res.status_code = EVMC_INVALID_INSTRUCTION;
        res.gas_left = 0;
        return res;
    }

    auto snapshot{state_.take_snapshot()};

    uint64_t block_num{block_.header.number};
    bool spurious_dragon{config().has_spurious_dragon(block_num)};

    state_.create_contract(contract_addr);
    if (spurious_dragon) {
        state_.set_nonce(contract_addr, 1);
    }

    state_.subtract_from_balance(message.sender, value);
    state_.add_to_balance(contract_addr, value);

    evmc_message deploy_message{
        EVMC_CALL,       // kind
        0,               // flags
        message.depth,   // depth
        message.gas,     // gas
        contract_addr,   // destination
        message.sender,  // sender
        nullptr,         // input_data
        0,               // input_size
        message.value,   // value
    };

    res = execute(deploy_message, ByteView{message.input_data, message.input_size}, /*code_hash=*/std::nullopt);

    if (res.status_code == EVMC_SUCCESS) {
        size_t code_len{res.output_size};
        uint64_t code_deploy_gas{code_len * fee::kGCodeDeposit};

        if (spurious_dragon && code_len > param::kMaxCodeSize) {
            // https://eips.ethereum.org/EIPS/eip-170
            res.status_code = EVMC_OUT_OF_GAS;
        } else if (res.gas_left >= 0 && static_cast<uint64_t>(res.gas_left) >= code_deploy_gas) {
            res.gas_left -= code_deploy_gas;
            state_.set_code(contract_addr, {res.output_data, res.output_size});
        } else if (config().has_homestead(block_num)) {
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
    evmc::result res{EVMC_SUCCESS, message.gas, nullptr, 0};

    auto value{intx::be::load<intx::uint256>(message.value)};
    if (message.kind != EVMC_DELEGATECALL && state_.get_balance(message.sender) < value) {
        res.status_code = static_cast<evmc_status_code>(EVMC_BALANCE_TOO_LOW);
        return res;
    }

    bool precompiled{is_precompiled(message.destination)};

    // https://eips.ethereum.org/EIPS/eip-161
    if (value == 0 && config().has_spurious_dragon(block_.header.number) && !state_.exists(message.destination) &&
        !precompiled) {
        return res;
    }

    auto snapshot{state_.take_snapshot()};

    if (message.kind == EVMC_CALL && !(message.flags & EVMC_STATIC)) {
        state_.subtract_from_balance(message.sender, value);
        state_.add_to_balance(message.destination, value);
    }

    if (precompiled) {
        uint8_t num{message.destination.bytes[kAddressLength - 1]};
        precompiled::Contract contract{precompiled::kContracts[num - 1]};
        ByteView input{message.input_data, message.input_size};
        int64_t gas = contract.gas(input, revision());
        if (gas < 0 || gas > message.gas) {
            res.status_code = EVMC_OUT_OF_GAS;
        } else {
            std::optional<Bytes> output{contract.run(input)};
            if (output) {
                res = {EVMC_SUCCESS, message.gas - gas, output->data(), output->size()};
            } else {
                res.status_code = EVMC_PRECOMPILE_FAILURE;
            }
        }
    } else {
        Bytes code{state_.get_code(message.destination)};
        if (code.empty()) {
            return res;
        }

        evmc::bytes32 code_hash{state_.get_code_hash(message.destination)};

        evmc_message msg{message};
        if (msg.kind == EVMC_CALLCODE) {
            msg.destination = msg.sender;
        } else if (msg.kind == EVMC_DELEGATECALL) {
            msg.destination = address_stack_.top();
        }

        res = execute(msg, code, code_hash);
    }

    if (res.status_code != EVMC_SUCCESS) {
        state_.revert_to_snapshot(snapshot);
        if (res.status_code != EVMC_REVERT) {
            res.gas_left = 0;
        }
    }

    return res;
}

evmc::result EVM::execute(const evmc_message& msg, ByteView code, std::optional<evmc::bytes32> code_hash) noexcept {
    address_stack_.push(msg.destination);

    EvmHost host{*this};
    evmc_revision rev{revision()};

    std::shared_ptr<evmone::code_analysis> analysis;
    if (code_hash) {
        // cache contract code
        analysis = AnalysisCache::instance().get(*code_hash, rev);
        if (!analysis) {
            analysis = std::make_shared<evmone::code_analysis>(evmone::analyze(rev, code.data(), code.size()));
            AnalysisCache::instance().put(*code_hash, analysis, rev);
        }
    } else {
        // don't cache deployment code
        analysis = std::make_shared<evmone::code_analysis>(evmone::analyze(rev, code.data(), code.size()));
    }

    auto state{ExecutionStatePool::instance().acquire()};
    state->clear();

    state->gas_left = msg.gas;
    state->msg = &msg;
    state->host = evmc::HostContext{host.get_interface(), host.to_context()};
    state->rev = rev;
    state->code = code;
    state->analysis = analysis.get();

    const auto* instruction{&state->analysis->instrs[0]};
    while (instruction) {
        instruction = instruction->fn(instruction, *state);
    }

    const uint8_t* output_data{state->output_size ? &state->memory[state->output_offset] : nullptr};
    evmc::result res{evmc::make_result(state->status, state->gas_left, output_data, state->output_size)};

    ExecutionStatePool::instance().release(std::move(state));

    address_stack_.pop();

    return res;
}

evmc_revision EVM::revision() const noexcept {
    uint64_t block_number{block_.header.number};

    if (config().has_istanbul(block_number)) return EVMC_ISTANBUL;
    if (config().has_petersburg(block_number)) return EVMC_PETERSBURG;
    if (config().has_constantinople(block_number)) return EVMC_CONSTANTINOPLE;
    if (config().has_byzantium(block_number)) return EVMC_BYZANTIUM;
    if (config().has_spurious_dragon(block_number)) return EVMC_SPURIOUS_DRAGON;
    if (config().has_tangerine_whistle(block_number)) return EVMC_TANGERINE_WHISTLE;
    if (config().has_homestead(block_number)) return EVMC_HOMESTEAD;

    return EVMC_FRONTIER;
}

uint8_t EVM::number_of_precompiles() const noexcept {
    uint64_t block_number{block_.header.number};

    if (config().has_istanbul(block_number)) {
        return precompiled::kNumOfIstanbulContracts;
    }
    if (config().has_byzantium(block_number)) {
        return precompiled::kNumOfByzantiumContracts;
    }

    return precompiled::kNumOfFrontierContracts;
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
    if (evm_.config().has_spurious_dragon(evm_.block_.header.number)) {
        return !evm_.state().dead(address);
    } else {
        return evm_.state().exists(address);
    }
}

evmc::bytes32 EvmHost::get_storage(const evmc::address& address, const evmc::bytes32& key) const noexcept {
    return evm_.state().get_current_storage(address, key);
}

evmc_storage_status EvmHost::set_storage(const evmc::address& address, const evmc::bytes32& key,
                                         const evmc::bytes32& new_val) noexcept {
    evmc::bytes32 current_val{evm_.state().get_current_storage(address, key)};

    if (current_val == new_val) {
        return EVMC_STORAGE_UNCHANGED;
    }

    evm_.state().set_storage(address, key, new_val);

    uint64_t block_number{evm_.block_.header.number};
    bool eip1283{evm_.config().has_istanbul(block_number) ||
                 (evm_.config().has_constantinople(block_number) && !evm_.config().has_petersburg(block_number))};

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

    uint64_t sload_cost{evm_.config().has_istanbul(block_number) ? fee::kGSLoadIstanbul : fee::kGSLoadTangerineWhistle};
    // https://eips.ethereum.org/EIPS/eip-1283
    evmc::bytes32 original_val{evm_.state().get_original_storage(address, key)};

    if (original_val == current_val) {
        if (is_zero(original_val)) {
            return EVMC_STORAGE_ADDED;
        }
        if (is_zero(new_val)) {
            evm_.state().add_refund(fee::kRSClear);
        }
        return EVMC_STORAGE_MODIFIED;
    } else {
        if (!is_zero(original_val)) {
            if (is_zero(current_val)) {
                evm_.state().subtract_refund(fee::kRSClear);
            }
            if (is_zero(new_val)) {
                evm_.state().add_refund(fee::kRSClear);
            }
        }
        if (original_val == new_val) {
            if (is_zero(original_val)) {
                evm_.state().add_refund(fee::kGSSet - sload_cost);
            } else {
                evm_.state().add_refund(fee::kGSReset - sload_cost);
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
    if (evm_.state().dead(address)) {
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
            // Go Ethereum returns CREATE output only in case of REVERT
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
    evmc_tx_context context;
    intx::be::store(context.tx_gas_price.bytes, evm_.txn_->gas_price);
    context.tx_origin = *evm_.txn_->from;
    context.block_coinbase = evm_.block_.header.beneficiary;
    context.block_number = evm_.block_.header.number;
    context.block_timestamp = evm_.block_.header.timestamp;
    context.block_gas_limit = evm_.block_.header.gas_limit;
    intx::be::store(context.block_difficulty.bytes, evm_.block_.header.difficulty);
    intx::be::store(context.chain_id.bytes, intx::uint256{evm_.config().chain_id});
    return context;
}

evmc::bytes32 EvmHost::get_block_hash(int64_t n) const noexcept {
    uint64_t base_number{evm_.block_.header.number};
    uint64_t new_size{base_number - n};
    assert(new_size <= 256);

    std::vector<evmc::bytes32>& hashes{evm_.block_hashes_};
    if (hashes.empty()) {
        hashes.push_back(evm_.block_.header.parent_hash);
    }

    uint64_t old_size{hashes.size()};
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
