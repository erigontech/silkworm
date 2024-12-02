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
#include <iomanip>
#include <optional>
#include <regex>
#include <string_view>
#include <variant>

#include <ethash/keccak.hpp>
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>


// intx does not include operator<< overloading for uint<N>
namespace intx {

template <unsigned N>
inline std::ostream& operator<<(std::ostream& out, const uint<N>& value) {
    out << "0x" << intx::hex(value);
    return out;
}

}  // namespace intx

namespace silkworm {


inline constexpr const char* kEarliestBlockId{"earliest"};
inline constexpr const char* kLatestBlockId{"latest"};
inline constexpr const char* kPendingBlockId{"pending"};
inline constexpr const char* kFinalizedBlockId{"finalized"};
inline constexpr const char* kSafeBlockId{"safe"};
inline constexpr const char* kLatestExecutedBlockId{"latestExecuted"};


class BlockNumOrHash {
public:
    explicit BlockNumOrHash(const std::string& block_num_or_hash) { build(block_num_or_hash); }
    explicit BlockNumOrHash(BlockNum block_num) noexcept : value_{block_num} {}

    virtual ~BlockNumOrHash() noexcept = default;

    BlockNumOrHash(const BlockNumOrHash&) noexcept = default;
    BlockNumOrHash& operator=(const BlockNumOrHash&) = default;

    BlockNumOrHash(BlockNumOrHash&&) = default;
    BlockNumOrHash& operator=(BlockNumOrHash&&) noexcept = default;

    bool is_number() const {
        return std::holds_alternative<uint64_t>(value_);
    }

    uint64_t number() const {
        return is_number() ? *std::get_if<uint64_t>(&value_) : 0;
    }

    bool is_hash() const {
        return std::holds_alternative<evmc::bytes32>(value_);
    }

    evmc::bytes32 hash() const {
        return is_hash() ? *std::get_if<evmc::bytes32>(&value_) : evmc::bytes32{0};
    }

    bool is_tag() const {
        return std::holds_alternative<std::string>(value_);
    }

    std::string tag() const {
        return is_tag() ? *std::get_if<std::string>(&value_) : "";
    }

private:
    void build(std::string const& block_num_or_hash);

    std::variant<uint64_t, evmc::bytes32, std::string> value_;
};
std::ostream& operator<<(std::ostream& out, const BlockNumOrHash& b);


//! \brief Strips leftmost zeroed bytes from byte sequence
//! \param [in] data : The view to process
//! \return A new view of the sequence
ByteView zeroless_view(ByteView data);

inline bool has_hex_prefix(std::string_view s) {
    return s.length() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
}

inline bool is_valid_hex(std::string_view s) {
    static const std::regex kHexRegex("^0x[0-9a-fA-F]+$");
    return std::regex_match(s.data(), kHexRegex);
}

inline bool is_valid_hash(std::string_view s) {
    if (s.length() != 2 + kHashLength * 2) {
        return false;
    }
    return is_valid_hex(s);
}

inline bool is_valid_address(std::string_view s) {
    if (s.length() != 2 + kAddressLength * 2) {
        return false;
    }
    return is_valid_hex(s);
}

//! \brief Returns a string representing the hex form of provided string of bytes
std::string to_hex(ByteView bytes, bool with_prefix = false);

//! \brief Returns a string representing the hex form of provided integral
template <typename T>
    requires(std::is_integral_v<T> && std::is_unsigned_v<T>)
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

std::optional<uint8_t> decode_hex_digit(char ch) noexcept;

std::optional<Bytes> from_hex(std::string_view hex) noexcept;

// Parses a string input value representing a size in
// human-readable format with qualifiers. eg "256MB"
std::optional<uint64_t> parse_size(const std::string& sizestr);

// Converts a number of bytes in a human-readable format
std::string human_size(uint64_t bytes, const char* unit = "B");

// Compares two strings for equality with case insensitivity
bool iequals(std::string_view a, std::string_view b);

// The length of the longest common prefix of a and b.
size_t prefix_length(ByteView a, ByteView b);

inline ethash::hash256 keccak256(ByteView view) { return ethash::keccak256(view.data(), view.size()); }

//! \brief Create an intx::uint256 from a string supporting both fixed decimal and scientific notation
template <UnsignedIntegral Int>
constexpr Int from_string_sci(const char* str) {
    auto s = str;
    auto m = Int{};

    int num_digits = 0;
    int num_decimal_digits = 0;
    bool count_decimals{false};
    char c = 0;
    while ((c = *s++)) {
        if (c == '.') {
            count_decimals = true;
            continue;
        }
        if (c == 'e') {
            if (*s++ != '+') intx::throw_<std::out_of_range>(s);
            break;
        }
        if (num_digits++ > std::numeric_limits<Int>::digits10) {
            intx::throw_<std::out_of_range>(s);
        }
        if (count_decimals) {
            ++num_decimal_digits;
        }

        const auto d = intx::from_dec_digit(c);
        m = m * Int{10} + d;
        if (m < d) {
            intx::throw_<std::out_of_range>(s);
        }
    }
    if (!c) {
        if (num_decimal_digits == 0) return m;
        intx::throw_<std::out_of_range>(s);
    }

    int e = 0;
    while ((c = *s++)) {
        const auto d = intx::from_dec_digit(c);
        e = e * 10 + d;
        if (e < d) {
            intx::throw_<std::out_of_range>(s);
        }
    }
    if (e < num_decimal_digits) {
        intx::throw_<std::out_of_range>(s);
    }

    auto x = m;
    auto exp = e - num_decimal_digits;
    while (exp > 0) {
        x *= Int{10};
        --exp;
    }
    return x;
}

inline std::ostream& operator<<(std::ostream& out, ByteView bytes) {
    for (const auto& b : bytes) {
        out << std::hex << std::setw(2) << std::setfill('0') << int{b};
    }
    out << std::dec;
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const Bytes& bytes) {
    out << to_hex(bytes);
    return out;
}

float to_float(const intx::uint256&) noexcept;

std::string snake_to_camel(std::string_view snake);

}  // namespace silkworm
