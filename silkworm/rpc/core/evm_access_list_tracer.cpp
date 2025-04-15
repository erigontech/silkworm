// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "evm_access_list_tracer.hpp"

#include <memory>

#include <evmc/hex.hpp>
#include <evmc/instructions.h>
#include <evmone/execution_state.hpp>
#include <evmone/instructions.hpp>
#include <evmone/instructions_traits.hpp>
#include <intx/intx.hpp>
#include <openssl/obj_mac.h>

#include <silkworm/core/execution/precompile.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {

static constexpr size_t kTxAccessListStorageKeyGas = 1900;  // per storage key specified in EIP 2930 access list
static constexpr size_t kTxAccessListAddressGas = 2400;     // per address specified in EIP 2930 access list

void AccessListTracer::on_instruction_start(uint32_t pc, const intx::uint256* stack_top, const int stack_height, int64_t gas,
                                            const evmone::ExecutionState& execution_state, const silkworm::IntraBlockState& intra_block_state) noexcept {
    SILKWORM_ASSERT(execution_state.msg);
    evmc::address recipient(execution_state.msg->recipient);

    const auto opcode = execution_state.original_code[pc];

    SILK_DEBUG << "on_instruction_start:"
               << " pc: " << std::dec << pc
               << " opcode: 0x" << std::hex << evmc::hex(opcode)
               << " recipient: " << recipient
               << " execution_state: {"
               << "   gas_left: " << std::dec << gas
               << "   status: " << execution_state.status
               << "   msg.gas: " << std::dec << execution_state.msg->gas
               << "   msg.depth: " << std::dec << execution_state.msg->depth
               << "}";

    if (is_storage_opcode(opcode) && stack_height >= 1) {
        evmc::bytes32 address;
        intx::be::store(address.bytes, stack_top[0]);
        if (!exclude(recipient, execution_state.rev)) {
            add_storage(recipient, address);
            if (!is_created_contract(recipient)) {
                use_address_on_old_contract(recipient);
            }
        }
    } else if (is_call_opcode(opcode) && stack_height >= 5) {
        evmc::address address;
        intx::be::trunc(address.bytes, stack_top[-1]);
        if (!exclude(address, execution_state.rev)) {
            add_address(address);
            if (!is_created_contract(address)) {
                use_address_on_old_contract(address);
            }
        }
    } else if (is_contract_opcode(opcode) && stack_height >= 1) {
        evmc::address address;
        intx::be::trunc(address.bytes, stack_top[0]);
        if (!exclude(address, execution_state.rev)) {
            add_address(address);
            if (!is_created_contract(address)) {
                use_address_on_old_contract(address);
            }
        }
    } else if (opcode == evmc_opcode::OP_CREATE) {
        const uint64_t nonce{intra_block_state.get_nonce(execution_state.msg->recipient)};
        const auto& contract_address{create_address(execution_state.msg->recipient, nonce)};
        add_contract(contract_address);

    } else if (opcode == evmc_opcode::OP_CREATE2) {
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

inline bool AccessListTracer::is_storage_opcode(const int opcode) {
    return (opcode == evmc_opcode::OP_SLOAD || opcode == evmc_opcode::OP_SSTORE);
}

inline bool AccessListTracer::is_contract_opcode(const int opcode) {
    return (opcode == evmc_opcode::OP_EXTCODECOPY || opcode == evmc_opcode::OP_EXTCODEHASH || opcode == evmc_opcode::OP_EXTCODESIZE ||
            opcode == evmc_opcode::OP_BALANCE || opcode == evmc_opcode::OP_SELFDESTRUCT);
}

inline bool AccessListTracer::is_call_opcode(const int opcode) {
    return (opcode == evmc_opcode::OP_DELEGATECALL || opcode == evmc_opcode::OP_CALL || opcode == evmc_opcode::OP_STATICCALL ||
            opcode == evmc_opcode::OP_CALLCODE);
}

inline bool AccessListTracer::exclude(const evmc::address& address, evmc_revision rev) {
    return (precompile::is_precompile(address, rev));
}


void AccessListTracer::add_address(const evmc::address& address) {
    SILK_DEBUG << "add_address:" << address;
    CreateAccessListEntry entry;
    create_access_list_.emplace(address, std::move(entry));
}

void AccessListTracer::add_storage(const evmc::address& address, const evmc::bytes32& storage) {
    SILK_DEBUG << "add_storage:" << address << " storage: " << to_hex(storage);
    auto it = create_access_list_.find(address);
    if (it != create_access_list_.end()) {
        SILK_DEBUG << "add_storage: new storage: " << address;
        auto& storage_keys = it->second.storage_keys;
        auto storage_it = storage_keys.find(storage);
        if (storage_it == storage_keys.end()) {
            storage_keys.emplace(storage, 1);
        }

    } else {
        SILK_DEBUG << "add_storage: new address: " << address;
        CreateAccessListEntry entry;
        entry.storage_keys.emplace(storage, 1);
        create_access_list_.emplace(address, std::move(entry));
    }
}

 AccessList AccessListTracer::get_access_list() const {
    AccessList access_list;

    access_list.reserve(create_access_list_.size());
    for (const auto& pair : create_access_list_) {
        const evmc::address& account = pair.first;
        const auto& [storage_keys] = pair.second;

        silkworm::AccessListEntry entry{account};

       entry.storage_keys.reserve(storage_keys.size());
        for (const auto& storage_pair : storage_keys) {
            entry.storage_keys.push_back(storage_pair.first);
        }

        access_list.push_back(std::move(entry));
    }
    return access_list;
}

void AccessListTracer::dump(const std::string& user_string, const CreateAccessList& acl) {
    std::cout << "Dump: " << user_string << "\n";
    for (const auto &pair : acl) {
        const evmc::address& account = pair.first;
        std::cout << "Address: " << account << "\n";
        const CreateAccessListEntry& createEntry = pair.second;
        for (const auto &storagePair : createEntry.storage_keys) {
            std::cout << "-> StorageKeys: " << to_hex(storagePair.first) << "\n";
        }
    }
    std::cout << "---------\n";
}

bool AccessListTracer::compare(const CreateAccessList& acl1, const CreateAccessList& acl2) {
    SILK_LOG << "compare:" << acl1.size() << " " << acl2.size();

        if (acl1.size() != acl2.size()) {
            return false;
        }
        for (const auto& pair : acl1) {
            const evmc::address& address = pair.first;
            const CreateAccessListEntry& entry_first_acl = pair.second;

            auto it = acl2.find(address);
            if (it == acl2.end()) {
                return false;
            }

            const CreateAccessListEntry& entry_second_acl = it->second;

            if (entry_first_acl.storage_keys.size() != entry_second_acl.storage_keys.size()) {
                return false;
            }

            for (const auto& storage_pair : entry_first_acl.storage_keys) {
                const evmc::bytes32& storage_key = storage_pair.first;

                auto it_storage = entry_second_acl.storage_keys.find(storage_key);
                if (it_storage == entry_second_acl.storage_keys.end()) {
                    return false;
                }
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
void AccessListTracer::optimize_gas(AccessList& access_list, const evmc::address& from, const evmc::address& to, const evmc::address& coinbase) {
    optimize_warm_address_in_access_list(access_list, from);
    optimize_warm_address_in_access_list(access_list, to);
    optimize_warm_address_in_access_list(access_list, coinbase);
    for (const auto& [address, _] : created_contracts_) {
        if (!used_before_creation_.contains(address)) {
            optimize_warm_address_in_access_list(access_list, address);
        }
    }
}

void AccessListTracer::optimize_warm_address_in_access_list(AccessList& access_list,  const evmc::address& address) {
    for (auto it = access_list.begin();
        it != access_list.end();
        ++it) {
        if (it->account == address) {
            // https://eips.ethereum.org/EIPS/eip-2930#charging-less-for-accesses-in-the-access-list
            size_t access_list_saving_per_slot = evmone::instr::cold_sload_cost - evmone::instr::warm_storage_read_cost - kTxAccessListStorageKeyGas;
            if (access_list_saving_per_slot * it->storage_keys.size() <= kTxAccessListAddressGas) {
                access_list.erase(it);
                return;
            }
        }
    }
}

}  // namespace silkworm::rpc
