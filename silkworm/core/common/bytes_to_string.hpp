// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
inline ByteView string_view_to_byte_view(std::string_view v) { return {byte_ptr_cast(v.data()), v.size()}; }

template <size_t Size>
ByteView array_to_byte_view(const std::array<unsigned char, Size>& array) {
    return ByteView{reinterpret_cast<const uint8_t*>(array.data()), Size};
}

inline std::string bytes_to_string(Bytes b) { return {b.begin(), b.end()}; }
inline std::string_view byte_view_to_string_view(ByteView v) { return {byte_ptr_cast(v.data()), v.size()}; }
inline std::span<const char> byte_view_to_str_span(ByteView v) { return {byte_ptr_cast(v.data()), v.size()}; }

}  // namespace silkworm
