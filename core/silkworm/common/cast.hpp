/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_COMMON_CAST_HPP_
#define SILKWORM_COMMON_CAST_HPP_

// Utilities for type casting

#include <cstring>
#include <type_traits>

#include <silkworm/common/base.hpp>

namespace silkworm {

// Cast between pointers to char and unsigned char (i.e. uint8_t)
inline char* byte_ptr_cast(uint8_t* ptr) { return reinterpret_cast<char*>(ptr); }
inline const char* byte_ptr_cast(const uint8_t* ptr) { return reinterpret_cast<const char*>(ptr); }
inline uint8_t* byte_ptr_cast(char* ptr) { return reinterpret_cast<uint8_t*>(ptr); }
inline const uint8_t* byte_ptr_cast(const char* ptr) { return reinterpret_cast<const uint8_t*>(ptr); }

// Backport of C++20 std::bit_cast
// https://en.cppreference.com/w/cpp/numeric/bit_cast
template <class To, class From>
typename std::enable_if_t<
    sizeof(To) == sizeof(From) && std::is_trivially_copyable_v<From> && std::is_trivially_copyable_v<To>, To>
bit_cast(const From& src) noexcept {
    To dst;
    std::memcpy(&dst, &src, sizeof(To));
    return dst;
}

}  // namespace silkworm

#endif  // SILKWORM_COMMON_CAST_HPP_
