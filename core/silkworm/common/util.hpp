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

#include <cmath>
#include <cstring>
#include <optional>
#include <string_view>
#include <vector>

#include <ethash/keccak.hpp>
#include <intx/intx.hpp>

#include <silkworm/common/base.hpp>

namespace silkworm {

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

inline bool has_hex_prefix(std::string_view s) {
    return s.length() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
}

//! \brief Returns a string representing the hex form of provided string of bytes
std::string to_hex(ByteView bytes, bool with_prefix = false);

//! \brief Returns a string representing the hex form of provided integral
template <typename T, typename = std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>>>
std::string to_hex(T value, bool with_prefix = false) {
    uint8_t bytes[sizeof(T)];
    intx::be::store(bytes, value);
    std::string hexed{to_hex(zeroless_view(bytes), with_prefix)};
    if (hexed.length() == (with_prefix ? 2 : 0)) {
        hexed += "00";
    }
    return hexed;
}

//! \brief Abridges a string to given length and eventually adds an ellipsis if input length is gt required length
std::string abridge(std::string_view input, size_t length);

std::optional<unsigned> decode_hex_digit(char ch) noexcept;

std::optional<Bytes> from_hex(std::string_view hex) noexcept;

// Parses a string input value representing a size in
// human-readable format with qualifiers. eg "256MB"
std::optional<uint64_t> parse_size(const std::string& sizestr);

// Converts a number of bytes in a human-readable format
std::string human_size(uint64_t bytes);

// Compares two strings for equality with case insensitivity
bool iequals(std::string_view a, std::string_view b);

// The length of the longest common prefix of a and b.
size_t prefix_length(ByteView a, ByteView b);

inline ethash::hash256 keccak256(ByteView view) { return ethash::keccak256(view.data(), view.size()); }

//! \brief Create an intx::uint256 from a string supporting both fixed decimal and scientific notation
template <typename Int>
inline constexpr Int from_string_sci(const char* str) {
    auto s = str;
    auto m = Int{};

    int num_digits = 0;
    int num_decimal_digits = 0;
    bool count_decimals{false};
    char c;
    while ((c = *s++)) {
        if (c == '.') {
            count_decimals = true;
            continue;
        }
        if (c == 'e') {
            if (*s++ != '+') intx::throw_<std::out_of_range>(s);
            break;
        }
        if (num_digits++ > std::numeric_limits<Int>::digits10)
            intx::throw_<std::out_of_range>(s);
        if (count_decimals) num_decimal_digits++;

        const auto d = intx::from_dec_digit(c);
        m = m * Int{10} + d;
        if (m < d)
            intx::throw_<std::out_of_range>(s);
    }
    if (!c) {
        if (num_decimal_digits == 0) return m;
        intx::throw_<std::out_of_range>(s);
    }

    int e = 0;
    while ((c = *s++)) {
        const auto d = intx::from_dec_digit(c);
        e = e * 10 + d;
        if (e < d)
            intx::throw_<std::out_of_range>(s);
    }
    if (e < num_decimal_digits)
        intx::throw_<std::out_of_range>(s);

    auto x = m;
    auto exp = e - num_decimal_digits;
    while (exp > 0) {
        x = x * Int{10};
        --exp;
    }
    return x;
}

}  // namespace silkworm
