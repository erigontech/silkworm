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

#include "util.hpp"

#include <algorithm>
#include <cstdio>
#include <regex>

#include <silkworm/core/common/assert.hpp>

namespace silkworm {

ByteView zeroless_view(ByteView data) {
    const auto is_zero_byte = [](const auto& b) { return b == 0x0; };
    const auto first_nonzero_byte_it{std::ranges::find_if_not(data, is_zero_byte)};
    return data.substr(static_cast<size_t>(std::distance(data.begin(), first_nonzero_byte_it)));
}

std::string to_hex(ByteView bytes, bool with_prefix) {
    static const char* kHexDigits{"0123456789abcdef"};
    std::string out(bytes.length() * 2 + (with_prefix ? 2 : 0), '\0');
    char* dest{&out[0]};
    if (with_prefix) {
        *dest++ = '0';
        *dest++ = 'x';
    }
    for (const auto& b : bytes) {
        *dest++ = kHexDigits[b >> 4];    // Hi
        *dest++ = kHexDigits[b & 0x0f];  // Lo
    }
    return out;
}

std::string abridge(std::string_view input, size_t length) {
    if (input.length() <= length) {
        return std::string(input);
    }
    return std::string(input.substr(0, length)) + "...";
}

std::optional<uint8_t> decode_hex_digit(char ch) noexcept {
    auto ret{internal::unhex_lut(static_cast<uint8_t>(ch))};
    if (ret == 0xff) {
        return std::nullopt;
    }
    return ret;
}

inline bool case_insensitive_char_comparer(char a, char b) { return (tolower(a) == tolower(b)); }

bool iequals(const std::string_view a, const std::string_view b) {
    return (a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), case_insensitive_char_comparer));
}

std::optional<uint64_t> parse_size(const std::string& sizestr) {
    if (sizestr.empty()) {
        return 0ull;
    }

    static const std::regex pattern{R"(^(\d*)(\.\d{1,3})?\ *?(B|KB|MB|GB|TB)?$)", std::regex_constants::icase};
    std::smatch matches;
    if (!std::regex_search(sizestr, matches, pattern, std::regex_constants::match_default)) {
        return std::nullopt;
    }

    std::string int_part, dec_part, suf_part;
    uint64_t multiplier{1};  // Default for bytes (B|b)

    int_part = matches[1].str();
    if (!matches[2].str().empty()) {
        dec_part = matches[2].str().substr(1);
    }
    suf_part = matches[3].str();

    if (!suf_part.empty()) {
        if (iequals(suf_part, "KB")) {
            multiplier = kKibi;
        } else if (iequals(suf_part, "MB")) {
            multiplier = kMebi;
        } else if (iequals(suf_part, "GB")) {
            multiplier = kGibi;
        } else if (iequals(suf_part, "TB")) {
            multiplier = kTebi;
        }
    }

    auto number{std::strtoull(int_part.c_str(), nullptr, 10)};
    number *= multiplier;
    if (!dec_part.empty()) {
        // Use literals, so we don't deal with floats and doubles
        auto base{"1" + std::string(dec_part.size(), '0')};
        auto b{std::strtoul(base.c_str(), nullptr, 10)};
        auto d{std::strtoul(dec_part.c_str(), nullptr, 10)};
        number += multiplier * d / b;
    }
    return number;
}

std::string human_size(uint64_t bytes, const char* unit) {
    static const char* suffix[]{"", "K", "M", "G", "T"};
    static const uint32_t items{sizeof(suffix) / sizeof(suffix[0])};
    uint32_t index{0};
    double value{static_cast<double>(bytes)};
    while (value >= kKibi) {
        value /= kKibi;
        if (++index == (items - 1)) {
            break;
        }
    }
    static constexpr size_t kBufferSize{64};
    SILKWORM_THREAD_LOCAL char output[kBufferSize];
    SILKWORM_ASSERT(std::snprintf(output, kBufferSize, "%.02lf %s%s", value, suffix[index], unit) > 0);
    return output;
}

size_t prefix_length(ByteView a, ByteView b) {
    size_t len{std::min(a.length(), b.length())};
    for (size_t i{0}; i < len; ++i) {
        if (a[i] != b[i]) {
            return i;
        }
    }
    return len;
}

float to_float(const intx::uint256& n) noexcept {
    static constexpr float k2_64{18446744073709551616.};  // 2^64
    const uint64_t* words{intx::as_words(n)};
    auto res{static_cast<float>(words[3])};
    res = k2_64 * res + static_cast<float>(words[2]);
    res = k2_64 * res + static_cast<float>(words[1]);
    res = k2_64 * res + static_cast<float>(words[0]);
    return res;
}

}  // namespace silkworm
