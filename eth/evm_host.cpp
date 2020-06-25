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

#include "evm_host.hpp"

#include <algorithm>

#include "protocol_param.hpp"

namespace silkworm::eth {

bool EvmHost::account_exists(const evmc::address& address) const noexcept {
  // TODO(Andrew) Do empty accounts require any special treatment (mind EIP-161)?
  return evm_.state().exists(address);
}

evmc::bytes32 EvmHost::get_storage(const evmc::address& address,
                                   const evmc::bytes32& key) const noexcept {
  return evm_.state().get_storage(address, key);
}

evmc_storage_status EvmHost::set_storage(const evmc::address& address, const evmc::bytes32& key,
                                         const evmc::bytes32& value) noexcept {
  const evmc::bytes32& prev_val = evm_.state().get_storage(address, key);

  if (prev_val == value) return EVMC_STORAGE_UNCHANGED;

  evm_.state().set_storage(address, key, value);

  if (is_zero(prev_val)) return EVMC_STORAGE_ADDED;

  if (is_zero(value)) {
    evm_.state().add_refund(fee::kRsclear);
    return EVMC_STORAGE_DELETED;
  }

  return EVMC_STORAGE_MODIFIED;

  // TODO(Andrew) EIP-2200
}

evmc::uint256be EvmHost::get_balance(const evmc::address& address) const noexcept {
  intx::uint256 balance = evm_.state().get_balance(address);
  return intx::be::store<evmc::uint256be>(balance);
}

size_t EvmHost::get_code_size(const evmc::address& address) const noexcept {
  return evm_.state().get_code(address).size();
}

evmc::bytes32 EvmHost::get_code_hash(const evmc::address& address) const noexcept {
  return evm_.state().get_code_hash(address);
}

size_t EvmHost::copy_code(const evmc::address& address, size_t code_offset, uint8_t* buffer_data,
                          size_t buffer_size) const noexcept {
  std::string_view code = evm_.state().get_code(address);

  if (code_offset >= code.size()) return 0;

  size_t n = std::min(buffer_size, code.size() - code_offset);
  std::copy_n(&code[code_offset], n, buffer_data);
  return n;
}

void EvmHost::selfdestruct(const evmc::address&, const evmc::address&) noexcept {
  // TODO(Andrew) implement
}

evmc::result EvmHost::call(const evmc_message& message) noexcept {
  // TODO(Andrew) implement
  return {EVMC_REVERT, message.gas, message.input_data, message.input_size};
}

evmc_tx_context EvmHost::get_tx_context() const noexcept {
  evmc_tx_context context;
  context.block_coinbase = evm_.coinbase();
  // TODO(Andrew) implement the rest
  return context;
}

evmc::bytes32 EvmHost::get_block_hash(int64_t) const noexcept {
  // TODO(Andrew) implement
  return {};
}

void EvmHost::emit_log(const evmc::address&, const uint8_t*, size_t, const evmc::bytes32[],
                       size_t) noexcept {
  // TODO(Andrew) implement
}

}  // namespace silkworm::eth
