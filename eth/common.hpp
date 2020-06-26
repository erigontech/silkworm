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

#ifndef SILKWORM_ETH_COMMON_H_
#define SILKWORM_ETH_COMMON_H_

#include <stddef.h>
#include <stdint.h>

#include <evmc/evmc.hpp>

namespace silkworm::eth {

using namespace evmc::literals;

constexpr evmc::bytes32 kEmptyHash =
    0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470_bytes32;

constexpr evmc::bytes32 kEmptyRoot =
    0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;

constexpr uint64_t kEther{1'000'000'000'000'000'000};  // = 10^18

constexpr size_t kHashLength{32};

constexpr size_t kAddressLength{20};

}  // namespace silkworm::eth

#endif  // SILKWORM_ETH_COMMON_H_
