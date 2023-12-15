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

#pragma once

#include <string>
#include <vector>

#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/rpc/core/rawdb/accessors.hpp>
#include <silkworm/rpc/types/block.hpp>
#include <silkworm/rpc/types/call.hpp>
#include <silkworm/rpc/types/transaction.hpp>

namespace silkworm::rpc {

class AccessListTracer : public silkworm::EvmTracer {
  public:
    AccessListTracer() = default;
    AccessListTracer(const AccessListTracer&) = delete;
    AccessListTracer& operator=(const AccessListTracer&) = delete;

    AccessList& get_access_list() { return access_list_; }

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override;
    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height, int64_t gas,
                              const evmone::ExecutionState& execution_state, const silkworm::IntraBlockState& intra_block_state) noexcept override;

    void reset_access_list() { access_list_.clear(); }
    AccessList& optimize_gas(const evmc::address& from, const evmc::address& to, const evmc::address& coinbase);
    static void dump(const std::string& user_string, const AccessList& acl);
    static bool compare(const AccessList& acl1, const AccessList& acl2);

  private:
    inline bool exclude(const evmc::address& address);
    static inline bool is_storage_opcode(const std::string& opcode_name);
    static inline bool is_contract_opcode(const std::string& opcode_name);
    static inline bool is_call_opcode(const std::string& opcode_name);

    void add_storage(const evmc::address& address, const evmc::bytes32& storage);
    void add_address(const evmc::address& address);
    bool is_created_contract(const evmc::address& address);
    void add_contract(const evmc::address& address);
    void use_address_on_old_contract(const evmc::address& address);
    void optimize_warm_address_in_access_list(const evmc::address& address);

    std::map<evmc::address, bool> created_contracts_;
    std::map<evmc::address, bool> used_before_creation_;
    AccessList access_list_;
    evmc_revision rev_;

    const char* const* opcode_names_ = nullptr;
};

inline bool operator!=(const AccessList& acl1, const AccessList& acl2) {
    return AccessListTracer::compare(acl1, acl2) == false;
}

inline bool operator==(const AccessList& acl1, const AccessList& acl2) {
    return AccessListTracer::compare(acl1, acl2);
}

}  // namespace silkworm::rpc
