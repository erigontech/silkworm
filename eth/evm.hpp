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

#ifndef SILKWORM_ETH_EVM_H_
#define SILKWORM_ETH_EVM_H_

#include <stdint.h>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <string>
#include <string_view>

#include "common.hpp"
#include "config.hpp"
#include "intra_block_state.hpp"

// TODO(Andrew) get rid of this when
// https://github.com/ethereum/evmc/pull/528
// is merged and released
enum evmc_status_code_extra { EVMC_BALANCE_TOO_LOW = 32 };

namespace silkworm::eth {

struct CallResult {
  evmc_status_code status{EVMC_SUCCESS};
  uint64_t gas_left{0};
};

struct CreateResult : public CallResult {
  std::string output;
};

class EVM {
 public:
  EVM(const EVM&) = delete;
  EVM& operator=(const EVM&) = delete;

  EVM(IntraBlockState& state, evmc::address coinbase, uint64_t block_number);

  const evmc::address& coinbase() const { return coinbase_; }
  uint64_t block_number() const { return block_number_; }

  const ChainConfig& config() const { return config_; }

  IntraBlockState& state() { return state_; }

  CreateResult create(const evmc::address& caller, std::string_view code, uint64_t gas,
                      const intx::uint256& value);

  CallResult call(const evmc::address& caller, const evmc::address& recipient,
                  std::string_view input, uint64_t gas, const intx::uint256& value);

 private:
  CreateResult execute(const evmc_message& message, std::string_view code);

  evmc_revision revision() const noexcept;

  IntraBlockState& state_;
  ChainConfig config_{kMainnetChainConfig};
  evmc::address coinbase_;
  uint64_t block_number_{0};

  // TODO (Andrew) get rid of this?
  int32_t stack_depth_{0};
};

// Yellow Paper, Section 7
evmc::address create_address(const evmc::address& caller, uint64_t nonce);

// https://eips.ethereum.org/EIPS/eip-1014
evmc::address create2_address(const evmc::address& caller, const evmc::bytes32& salt,
                              const evmc::bytes32& code_hash);

}  // namespace silkworm::eth

#endif  // SILKWORM_ETH_EVM_H_
