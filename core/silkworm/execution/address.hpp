/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_EXECUTION_ADDRESS_HPP_
#define SILKWORM_EXECUTION_ADDRESS_HPP_

#include <silkworm/common/base.hpp>

namespace silkworm {
// Yellow Paper, Section 7
evmc::address create_address(const evmc::address& caller, uint64_t nonce) noexcept;

// https://eips.ethereum.org/EIPS/eip-1014
evmc::address create2_address(const evmc::address& caller, const evmc::bytes32& salt,
                              uint8_t (&code_hash)[32]) noexcept;
}  // namespace silkworm

#endif  // SILKWORM_EXECUTION_ADDRESS_HPP_
