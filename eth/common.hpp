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

#include <array>
#include <gsl/span>
#include <string_view>

namespace silkworm::eth {

constexpr uint64_t kEther{1'000'000'000'000'000'000};  // = 10^18

constexpr size_t kAddressLength{20};

using Address = std::array<char, kAddressLength>;

using AddressRef = gsl::span<const char, kAddressLength>;

// input will be truncated if necessary
Address hex_to_address(std::string_view hex);

}  // namespace silkworm::eth

#endif  // SILKWORM_ETH_COMMON_H_
