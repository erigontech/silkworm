/*
   Copyright 2023 The Silkworm Authors

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

#include "evm_access_list_tracer.hpp"

#include <memory>

#include <evmc/hex.hpp>
#include <evmc/instructions.h>
#include <evmone/execution_state.hpp>
#include <evmone/instructions.hpp>
#include <evmone/instructions_traits.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/execution/precompile.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {

const char* SLOAD = evmone::instr::traits[evmc_opcode::OP_SLOAD].name;
const char* SSTORE = evmone::instr::traits[evmc_opcode::OP_SSTORE].name;
const char* EXTCODECOPY = evmone::instr::traits[evmc_opcode::OP_EXTCODECOPY].name;
const char* EXTCODEHASH = evmone::instr::traits[evmc_opcode::OP_EXTCODEHASH].name;
const char* EXTCODESIZE = evmone::instr::traits[evmc_opcode::OP_EXTCODESIZE].name;
const char* BALANCE = evmone::instr::traits[evmc_opcode::OP_BALANCE].name;
const char* SELFDESTRUCT = evmone::instr::traits[evmc_opcode::OP_SELFDESTRUCT].name;
const char* DELEGATECALL = evmone::instr::traits[evmc_opcode::OP_DELEGATECALL].name;
const char* CALL = evmone::instr::traits[evmc_opcode::OP_CALL].name;
const char* STATICCALL = evmone::instr::traits[evmc_opcode::OP_STATICCALL].name;
const char* CALLCODE = evmone::instr::traits[evmc_opcode::OP_CALLCODE].name;
const char* CREATE = evmone::instr::traits[evmc_opcode::OP_CREATE].name;
const char* CREATE2 = evmone::instr::traits[evmc_opcode::OP_CREATE2].name;

inline constexpr auto kTxAccessListStorageKeyGas = 1900;  // per storage key specified in EIP 2930 access list
inline constexpr auto kTxAccessListAddressGas = 2400;     // per address specified in EIP 2930 access list

std::string get_opcode_name(const char* const* names, std::uint8_t opcode) {
    const auto name = names[opcode];
    return (name != nullptr) ? name : "opcode 0x" + evmc::hex(opcode) + " not defined";
}

void AccessListTracer::on_execution_start(evmc_revision rev, const evmc_message& /* msg */, evmone::bytes_view /*code*/) noexcept {
    if (opcode_names_ == nullptr) {
        opcode_names_ = evmc_get_instruction_names_table(rev);
    }
}

void AccessListTracer::on_instruction_start(uint32_t pc, const intx::uint256* stack_top, const int stack_height, int64_t gas,
                                            const evmone::ExecutionState& execution_state, const silkworm::IntraBlockState& intra_block_state) noexcept {
    assert(execution_state.msg);
    evmc::address recipient(execution_state.msg->recipient);

    const auto opcode = execution_state.original_code[pc];
    const auto opcode_name = get_opcode_name(opcode_names_, opcode);

    SILK_DEBUG << "on_instruction_start:"
               << " pc: " << std::dec << pc
               << " opcode: 0x" << std::hex << evmc::hex(opcode)
               << " opcode_name: " << opcode_name
               << " recipient: " << recipient
               << " execution_state: {"
               << "   gas_left: " << std::dec << gas
               << "   status: " << execution_state.status
               << "   msg.gas: " << std::dec << execution_state.msg->gas
               << "   msg.depth: " << std::dec << execution_state.msg->depth
               << "}";

    if (is_storage_opcode(opcode_name) && stack_height >= 1) {
        const auto address = silkworm::bytes32_from_hex(intx::hex(stack_top[0]));
        if (!exclude(recipient, execution_state.rev)) {
            add_storage(recipient, address);
            if (!is_created_contract(recipient)) {
                use_address_on_old_contract(recipient);
            }
        }
    } else if (is_contract_opcode(opcode_name) && stack_height >= 1) {
        evmc::address address;
        intx::be::trunc(address.bytes, stack_top[0]);
        if (!exclude(address, execution_state.rev)) {
            add_address(address);
            if (!is_created_contract(address)) {
                use_address_on_old_contract(address);
            }
        }
    } else if (is_call_opcode(opcode_name) && stack_height >= 5) {
        evmc::address address;
        intx::be::trunc(address.bytes, stack_top[-1]);
        if (!exclude(address, execution_state.rev)) {
            add_address(address);
            if (!is_created_contract(address)) {
                use_address_on_old_contract(address);
            }
        }
    } else if (opcode_name == CREATE) {
        const uint64_t nonce{intra_block_state.get_nonce(execution_state.msg->recipient)};
        const auto& contract_address{create_address(execution_state.msg->recipient, nonce)};
        add_contract(contract_address);

    } else if (opcode_name == CREATE2) {
        if (stack_height < 4) {
            return;  // Invariant break for current implementation of OP_CREATE2, let's handle this gracefully.
        }
        const auto init_code_offset = static_cast<size_t>(stack_top[-1]);
        if (init_code_offset >= execution_state.memory.size()) {
            return;  // Invariant break for current implementation of OP_CREATE2, let's handle this gracefully.
        }
        const auto init_code_size = static_cast<size_t>(stack_top[-2]);
        const evmc::bytes32 salt2{intx::be::store<evmc::bytes32>(stack_top[-3])};
        auto init_code_hash{
            init_code_size > 0 ? ethash::keccak256(&execution_state.memory.data()[init_code_offset], init_code_size) : ethash_hash256{}};
        const auto& contract_address{create2_address(execution_state.msg->recipient, salt2, init_code_hash.bytes)};
        add_contract(contract_address);
    }
}

inline bool AccessListTracer::is_storage_opcode(const std::string& opcode_name) {
    return (opcode_name == SLOAD || opcode_name == SSTORE);
}

inline bool AccessListTracer::is_contract_opcode(const std::string& opcode_name) {
    return (opcode_name == EXTCODECOPY || opcode_name == EXTCODEHASH || opcode_name == EXTCODESIZE ||
            opcode_name == BALANCE || opcode_name == SELFDESTRUCT);
}

inline bool AccessListTracer::is_call_opcode(const std::string& opcode_name) {
    return (opcode_name == DELEGATECALL || opcode_name == CALL || opcode_name == STATICCALL || opcode_name == CALLCODE);
}

inline bool AccessListTracer::exclude(const evmc::address& address, evmc_revision rev) {
    return (precompile::is_precompile(address, rev));
}

void AccessListTracer::add_storage(const evmc::address& address, const evmc::bytes32& storage) {
    SILK_TRACE << "add_storage:" << address << " storage: " << to_hex(storage);
    for (std::size_t i{0}; i < access_list_.size(); i++) {
        if (access_list_[i].account == address) {
            for (const auto& storage_key : access_list_[i].storage_keys) {
                if (storage_key == storage) {
                    return;
                }
            }
            access_list_[i].storage_keys.push_back(storage);
            return;
        }
    }
    silkworm::AccessListEntry item;
    item.account = address;
    item.storage_keys.push_back(storage);
    access_list_.push_back(item);
}

void AccessListTracer::add_address(const evmc::address& address) {
    SILK_TRACE << "add_address:" << address;
    for (std::size_t i{0}; i < access_list_.size(); i++) {
        if (access_list_[i].account == address) {
            return;
        }
    }
    silkworm::AccessListEntry item;
    item.account = address;
    access_list_.push_back(item);
}

void AccessListTracer::dump(const std::string& user_string, const AccessList& acl) {
    std::cout << "Dump: " << user_string << "\n";
    for (std::size_t i{0}; i < acl.size(); i++) {
        std::cout << "Address: " << acl[i].account << "\n";
        for (std::size_t z{0}; z < acl[i].storage_keys.size(); z++) {
            std::cout << "-> StorageKeys: " << to_hex(acl[i].storage_keys[z]) << "\n";
        }
    }
    std::cout << "---------\n";
}

bool AccessListTracer::compare(const AccessList& acl1, const AccessList& acl2) {
    if (acl1.size() != acl2.size()) {
        return false;
    }
    for (std::size_t i{0}; i < acl1.size(); i++) {
        bool match_address = false;
        for (std::size_t j{0}; j < acl2.size(); j++) {
            if (acl2[j].account == acl1[i].account) {
                match_address = true;
                if (acl2[j].storage_keys.size() != acl1[i].storage_keys.size()) {
                    return false;
                }
                bool match_storage = false;
                for (std::size_t z{0}; z < acl1[i].storage_keys.size(); z++) {
                    for (std::size_t t{0}; t < acl2[j].storage_keys.size(); t++) {
                        if (acl2[j].storage_keys[t] == acl1[i].storage_keys[z]) {
                            match_storage = true;
                            break;
                        }
                    }
                    if (!match_storage) {
                        return false;
                    }
                }
                break;
            }
        }
        if (!match_address) {
            return false;
        }
    }
    return true;
}

bool AccessListTracer::is_created_contract(const evmc::address& address) {
    return created_contracts_.find(address) != created_contracts_.end();
}

void AccessListTracer::add_contract(const evmc::address& address) {
    if (created_contracts_.find(address) != created_contracts_.end()) {
        created_contracts_[address] = true;
    }
}

void AccessListTracer::use_address_on_old_contract(const evmc::address& address) {
    if (used_before_creation_.find(address) != used_before_creation_.end()) {
        used_before_creation_[address] = true;
    }
}

// some addresses (like sender, recipient, block producer, and created contracts)
// are considered warm already, so we can save by adding these to the access list
// only if we are adding a lot of their respective storage slots as well
void AccessListTracer::optimize_gas(const evmc::address& from, const evmc::address& to, const evmc::address& coinbase) {
    optimize_warm_address_in_access_list(from);
    optimize_warm_address_in_access_list(to);
    optimize_warm_address_in_access_list(coinbase);
    for (auto it = created_contracts_.begin();
         it != created_contracts_.end();
         it++) {
        auto usedit = used_before_creation_.find(it->first);
        if (usedit == used_before_creation_.end()) {
            optimize_warm_address_in_access_list(it->first);
        }
    }
}

void AccessListTracer::optimize_warm_address_in_access_list(const evmc::address& address) {
    for (auto it = access_list_.begin();
         it != access_list_.end();
         it++) {
        if (it->account == address) {
            // https://eips.ethereum.org/EIPS/eip-2930#charging-less-for-accesses-in-the-access-list
            size_t access_list_saving_per_slot = evmone::instr::cold_sload_cost - evmone::instr::warm_storage_read_cost - kTxAccessListStorageKeyGas;
            if (access_list_saving_per_slot * it->storage_keys.size() <= kTxAccessListAddressGas) {
                access_list_.erase(it);
                return;
            }
        }
    }
}

}  // namespace silkworm::rpc
