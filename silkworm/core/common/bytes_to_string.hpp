/*
   Copyright 2022 The Silkworm Authors

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

#pragma once

// Utilities for type casting

#include <span>
#include <string_view>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace silkworm {

// Cast between pointers to char and unsigned char (i.e. uint8_t)
inline char* byte_ptr_cast(uint8_t* ptr) { return reinterpret_cast<char*>(ptr); }
inline const char* byte_ptr_cast(const uint8_t* ptr) { return reinterpret_cast<const char*>(ptr); }
inline uint8_t* byte_ptr_cast(char* ptr) { return reinterpret_cast<uint8_t*>(ptr); }
inline const uint8_t* byte_ptr_cast(const char* ptr) { return reinterpret_cast<const uint8_t*>(ptr); }

inline Bytes string_to_bytes(const std::string& s) { return {s.begin(), s.end()}; }
inline ByteView string_view_to_byte_view(std::string_view v) { return {byte_ptr_cast(v.data()), v.length()}; }

template <size_t Size>
ByteView array_to_byte_view(const std::array<unsigned char, Size>& array) {
    return ByteView{reinterpret_cast<const uint8_t*>(array.data()), Size};
}

inline std::string bytes_to_string(Bytes b) { return {b.begin(), b.end()}; }
inline std::string_view byte_view_to_string_view(ByteView v) { return {byte_ptr_cast(v.data()), v.length()}; }
inline std::span<const char> byte_view_to_str_span(ByteView v) { return {byte_ptr_cast(v.data()), v.length()}; }

}  // namespace silkworm
