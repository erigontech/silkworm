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

#ifndef SILKWORM_COMMON_UTIL_HPP_
#define SILKWORM_COMMON_UTIL_HPP_

#include <cstring>
#include <optional>
#include <string_view>
#include <vector>

#include <ethash/keccak.hpp>

#include <silkworm/common/base.hpp>

namespace silkworm {

// If a given string is shorter than min_size,
// pads it to the left with 0s up to min_size.
// Otherwise, returns unmodified string.
//
// Might return a view of the supplied buffer,
// which must be consumed prior to the next invocation.
// However, an already padded view may be padded again.
ByteView left_pad(ByteView view, size_t min_size, Bytes& buffer);

// If a given string is shorter than min_size,
// pads it to the right with 0s up to min_size.
// Otherwise, returns unmodified string.
//
// Might return a view of the supplied buffer,
// which must be consumed prior to the next invocation.
// However, an already padded view may be padded again.
ByteView right_pad(ByteView view, size_t min_size, Bytes& buffer);

// Converts bytes to evmc::address; input is cropped if necessary.
// Short inputs are left-padded with 0s.
evmc::address to_evmc_address(ByteView bytes);

// Converts bytes to evmc::bytes32; input is cropped if necessary.
// Short inputs are left-padded with 0s.
evmc::bytes32 to_bytes32(ByteView bytes);

//! \brief Strips leftmost zeroed bytes from byte sequence
//! \param [in] data : The view to process
//! \return A new view of the sequence
ByteView zeroless_view(ByteView data);

std::string to_hex(ByteView bytes);

std::optional<unsigned> decode_hex_digit(char ch) noexcept;

std::optional<Bytes> from_hex(std::string_view hex) noexcept;

// Parses a string input value representing a size in
// human-readable format with qualifiers. eg "256MB"
std::optional<uint64_t> parse_size(const std::string& sizestr);

// Converts a number of bytes in a human-readable format
std::string human_size(uint64_t bytes);

// Compares two strings for equality with case insensitivity
bool iequals(const std::string& a, const std::string& b);

// TODO[C++20] replace by starts_with
inline bool has_prefix(ByteView s, ByteView prefix) { return s.substr(0, prefix.size()) == prefix; }

// The length of the longest common prefix of a and b.
size_t prefix_length(ByteView a, ByteView b);

inline ethash::hash256 keccak256(ByteView view) { return ethash::keccak256(view.data(), view.size()); }

// Splits a string by delimiter and returns a vector of tokens
std::vector<std::string> split(std::string_view source, std::string_view delimiter);

}  // namespace silkworm

#endif  // SILKWORM_COMMON_UTIL_HPP_
