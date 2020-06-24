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

namespace silkworm::eth {

EVM::EVM(IntraBlockState& state, evmc::address coinbase, uint64_t block_number)
    : state_{state}, coinbase_{coinbase}, block_number_{block_number} {}

CallResult EVM::Create(const evmc::address&, std::string_view, uint64_t, const intx::uint256&) {
  CallResult res;
  // TODO(Andrew) implement
  return res;
}

CallResult EVM::Call(const evmc::address&, const evmc::address&, std::string_view, uint64_t,
                     const intx::uint256&) {
  CallResult res;
  // TODO(Andrew) implement
  return res;
}

}  // namespace silkworm::eth
