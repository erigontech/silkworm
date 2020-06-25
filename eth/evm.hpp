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
#include <string_view>

#include "common.hpp"
#include "config.hpp"
#include "intra_block_state.hpp"

// TODO(Andrew) merge back into evmc_status_code
enum evmc_status_code_extra { EVMC_NOT_ENOUGH_FUNDS = 32 };

namespace silkworm::eth {

struct CallResult {
  uint64_t remaining_gas{0};
  evmc_status_code status{EVMC_SUCCESS};
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

  CallResult create(const evmc::address& caller, std::string_view code, uint64_t gas,
                    const intx::uint256& value);

  CallResult call(const evmc::address& caller, const evmc::address& recipient,
                  std::string_view input, uint64_t gas, const intx::uint256& value);

 private:
  IntraBlockState& state_;
  ChainConfig config_{kMainnetChainConfig};
  evmc::address coinbase_;
  uint64_t block_number_{0};
  size_t stack_depth_{0};
};

}  // namespace silkworm::eth

#endif  // SILKWORM_ETH_EVM_H_
