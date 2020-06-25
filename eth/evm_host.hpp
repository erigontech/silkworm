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

#ifndef SILKWORM_ETH_EVM_HOST_H_
#define SILKWORM_ETH_EVM_HOST_H_

#include <evmc/evmc.hpp>

#include "evm.hpp"

namespace silkworm::eth {

class EvmHost : public evmc::Host {
 public:
  explicit EvmHost(EVM& evm) : evm_{evm} {}

  bool account_exists(const evmc::address& address) const noexcept override;

  evmc::bytes32 get_storage(const evmc::address& address, const evmc::bytes32& key) const
      noexcept override;

  evmc_storage_status set_storage(const evmc::address& address, const evmc::bytes32& key,
                                  const evmc::bytes32& value) noexcept override;

  evmc::uint256be get_balance(const evmc::address& address) const noexcept override;

  size_t get_code_size(const evmc::address& address) const noexcept override;

  evmc::bytes32 get_code_hash(const evmc::address& address) const noexcept override;

  size_t copy_code(const evmc::address& address, size_t code_offset, uint8_t* buffer_data,
                   size_t buffer_size) const noexcept override;

  void selfdestruct(const evmc::address& address,
                    const evmc::address& beneficiary) noexcept override;

  evmc::result call(const evmc_message& message) noexcept override;

  evmc_tx_context get_tx_context() const noexcept override;

  evmc::bytes32 get_block_hash(int64_t block_number) const noexcept override;

  void emit_log(const evmc::address& address, const uint8_t* data, size_t data_size,
                const evmc::bytes32 topics[], size_t num_topics) noexcept override;

 private:
  EVM& evm_;
};

}  // namespace silkworm::eth

#endif  // SILKWORM_ETH_EVM_HOST_H_
