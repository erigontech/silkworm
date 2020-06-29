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

#include <algorithm>
#include <cstring>
#include <evmc/evmc.hpp>
#include <string_view>

namespace silkworm::eth {

using namespace evmc::literals;

constexpr evmc::bytes32 kEmptyHash =
    0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470_bytes32;

constexpr evmc::bytes32 kEmptyRoot =
    0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;

constexpr uint64_t kEther{1'000'000'000'000'000'000};  // = 10^18

constexpr size_t kHashLength{32};

constexpr size_t kAddressLength{20};

inline char* byte_pointer_cast(uint8_t* ptr) noexcept { return reinterpret_cast<char*>(ptr); }
inline const char* byte_pointer_cast(const uint8_t* ptr) noexcept {
  return reinterpret_cast<const char*>(ptr);
}
inline uint8_t* byte_pointer_cast(char* ptr) noexcept { return reinterpret_cast<uint8_t*>(ptr); }
inline const uint8_t* byte_pointer_cast(const char* ptr) noexcept {
  return reinterpret_cast<const uint8_t*>(ptr);
}

inline evmc::bytes32 bytes_to_hash(std::string_view bytes) {
  evmc::bytes32 out;
  size_t n = std::min(bytes.length(), kHashLength);
  std::memcpy(out.bytes + kHashLength - n, bytes.data(), n);
  return out;
}

inline std::string_view hash_to_string_view(const evmc::bytes32& hash) {
  return {byte_pointer_cast(hash.bytes), kHashLength};
}

}  // namespace silkworm::eth

#endif  // SILKWORM_ETH_COMMON_H_
