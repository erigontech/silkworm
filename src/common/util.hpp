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

#ifndef SILKWORM_COMMON_UTIL_H_
#define SILKWORM_COMMON_UTIL_H_

#include <algorithm>
#include <boost/algorithm/hex.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/stream.hpp>
#include <cstring>
#include <evmc/evmc.hpp>

#include "const.hpp"

namespace silkworm {

static_assert(sizeof(char) == sizeof(uint8_t));

inline char* byte_ptr_cast(uint8_t* ptr) noexcept { return reinterpret_cast<char*>(ptr); }
inline const char* byte_ptr_cast(const uint8_t* ptr) noexcept {
  return reinterpret_cast<const char*>(ptr);
}
inline uint8_t* byte_ptr_cast(char* ptr) noexcept { return reinterpret_cast<uint8_t*>(ptr); }
inline const uint8_t* byte_ptr_cast(const char* ptr) noexcept {
  return reinterpret_cast<const uint8_t*>(ptr);
}

inline evmc::bytes32 to_hash(std::string_view bytes) {
  evmc::bytes32 out;
  size_t n = std::min(bytes.length(), kHashLength);
  std::memcpy(out.bytes + kHashLength - n, bytes.data(), n);
  return out;
}

inline std::string_view full_view(const evmc::address& address) {
  return {byte_ptr_cast(address.bytes), kAddressLength};
}

inline std::string_view full_view(const evmc::bytes32& hash) {
  return {byte_ptr_cast(hash.bytes), kHashLength};
}

// Leading zero bytes are stripped
std::string_view zeroless_view(const evmc::bytes32& hash);

inline std::string to_hex(const evmc::address& address) {
  return boost::algorithm::hex_lower(std::string{full_view(address)});
}

inline std::string to_hex(const evmc::bytes32& hash) {
  return boost::algorithm::hex_lower(std::string{full_view(hash)});
}

inline std::string to_hex(const std::string& str) { return boost::algorithm::hex_lower(str); }

inline boost::iostreams::stream<boost::iostreams::basic_array_source<char>> as_stream(
    std::string_view sv) {
  return {sv.begin(), sv.size()};
}
}  // namespace silkworm

#endif  // SILKWORM_COMMON_UTIL_H_
