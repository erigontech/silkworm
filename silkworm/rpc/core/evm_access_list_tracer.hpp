// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>
#include <unordered_map>

#include <evmone/test/state/transaction.hpp>

#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/rpc/types/call.hpp>

namespace silkworm::rpc {


struct CreateAccessListEntry {
    std::unordered_map<evmc::bytes32, int> storage_keys;

    bool operator==(const CreateAccessListEntry& other) const {
        return storage_keys == other.storage_keys;
    }
};
using CreateAccessList = std::unordered_map<evmc::address, CreateAccessListEntry>;


class AccessListTracer : public silkworm::EvmTracer {
public:
    AccessListTracer() = default;
    AccessListTracer(const AccessListTracer&) = delete;
    AccessListTracer& operator=(const AccessListTracer&) = delete;

    const AccessList& get_access_list() {
        convert_access_list();
        return access_list_;
    }

    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height, int64_t gas,
                              const evmone::ExecutionState& execution_state, const silkworm::IntraBlockState& intra_block_state) noexcept override;

    void reset_access_list() { create_access_list_.clear(); }
    void optimize_gas(const evmc::address& from, const evmc::address& to, const evmc::address& coinbase);
    static void dump(const std::string& user_string, const CreateAccessList& acl);
    static bool compare(const CreateAccessList& acl1, const CreateAccessList& acl2);

  private:
    static inline bool exclude(const evmc::address& address, evmc_revision rev);
    static inline bool is_storage_opcode(int opcode);
    static inline bool is_contract_opcode(int opcode);
    static inline bool is_call_opcode(int opcode);
    void convert_access_list();

    void add_storage(const evmc::address& address, const evmc::bytes32& storage);
    void add_address(const evmc::address& address);
    bool is_created_contract(const evmc::address& address);
    void add_contract(const evmc::address& address);
    void use_address_on_old_contract(const evmc::address& address);
    void optimize_warm_address_in_access_list(const evmc::address& address);

    std::map<evmc::address, bool> created_contracts_;
    std::map<evmc::address, bool> used_before_creation_;
    CreateAccessList create_access_list_;

    AccessList access_list_;
};

inline bool operator!=(const CreateAccessList& acl1, const CreateAccessList& acl2) {
    return !AccessListTracer::compare(acl1, acl2);
}

inline bool operator==(const CreateAccessList& acl1, const CreateAccessList& acl2) {
    return AccessListTracer::compare(acl1, acl2);
    //return acl1 == acl2;
}

}  // namespace silkworm::rpc
