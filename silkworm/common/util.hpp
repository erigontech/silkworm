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

#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/stream.hpp>
#include <silkworm/common/base.hpp>

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

evmc::bytes32 to_hash(ByteView bytes);

template <unsigned N>
ByteView full_view(const uint8_t (&bytes)[N]) {
  return {bytes, N};
}

inline ByteView full_view(const evmc::address& address) { return {address.bytes, kAddressLength}; }
inline ByteView full_view(const evmc::bytes32& hash) { return {hash.bytes, kHashLength}; }

// Leading zero bytes are stripped
ByteView zeroless_view(const evmc::bytes32& hash);

std::string to_hex(const evmc::address& address);
std::string to_hex(const evmc::bytes32& hash);
std::string to_hex(ByteView bytes);

Bytes from_hex(std::string_view hex);

// TODO[C++20] replace by starts_with
inline bool has_prefix(ByteView s, ByteView prefix) { return s.substr(0, prefix.size()) == prefix; }

// TODO[C++20] replace by std::popcount
inline int popcount(unsigned x) {
#ifdef _MSC_VER
  return __popcnt(x);
#else
  return __builtin_popcount(x);
#endif
}

inline boost::iostreams::stream<boost::iostreams::basic_array_source<char>> as_stream(
    ByteView view) {
  return {byte_ptr_cast(view.begin()), view.size()};
}
}  // namespace silkworm

#endif  // SILKWORM_COMMON_UTIL_H_
