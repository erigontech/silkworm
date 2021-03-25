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

#ifndef SILKWORM_COMMON_BASE_HPP_
#define SILKWORM_COMMON_BASE_HPP_

// The most common and basic types and constants.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <string_view>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#include <evmc/evmc.hpp>
#pragma GCC diagnostic pop

namespace silkworm {

using namespace evmc::literals;

using Bytes = std::basic_string<uint8_t>;

using ByteView = std::basic_string_view<uint8_t>;

constexpr size_t kAddressLength{20};

constexpr size_t kHashLength{32};

// Keccak-256 hash of an empty string, KEC("").
constexpr evmc::bytes32 kEmptyHash{0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470_bytes32};

// Keccak-256 hash of the RLP of an empty list, KEC("\xc0").
constexpr evmc::bytes32 kEmptyListHash{0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347_bytes32};

// Root hash of an empty trie.
constexpr evmc::bytes32 kEmptyRoot{0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32};

// https://en.wikipedia.org/wiki/Binary_prefix
constexpr uint64_t kKibi{1024};
constexpr uint64_t kMebi{1024 * kKibi};
constexpr uint64_t kGibi{1024 * kMebi};
constexpr uint64_t kTebi{1024 * kGibi};

constexpr uint64_t kGiga{1'000'000'000};   // = 10^9
constexpr uint64_t kEther{kGiga * kGiga};  // = 10^18

}  // namespace silkworm

#endif  // SILKWORM_COMMON_BASE_HPP_
