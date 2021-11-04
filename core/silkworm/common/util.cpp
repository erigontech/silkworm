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

#include "util.hpp"
#include <silkworm/common/as_range.hpp>

#include <cassert>
#include <regex>

namespace silkworm {

// ASCII -> hex value (0xbc means bad [hex] char)
static constexpr uint8_t kUnhexTable[256] = {
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc};

// ASCII -> hex value << 4 (upper nibble) (0xbc means bad [hex] char)
static constexpr uint8_t kUnhexTable4[256] = {
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
    0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc};

ByteView left_pad(ByteView view, size_t min_size, Bytes& buffer) {
    if (view.size() >= min_size) {
        return view;
    }

    if (buffer.size() < min_size) {
        buffer.resize(min_size);
    } else {
        // view & buffer might overlap in memory,
        // so we avoid shrinking the buffer prior to the memmove
    }

    assert(view.size() < min_size);
    size_t prefix_len{min_size - view.size()};

    // view & buffer might overlap in memory,
    // thus memmove instead of memcpy
    std::memmove(buffer.data() + prefix_len, view.data(), view.size());

    buffer.resize(min_size);
    std::memset(buffer.data(), 0, prefix_len);

    return buffer;
}

ByteView right_pad(ByteView view, size_t min_size, Bytes& buffer) {
    if (view.size() >= min_size) {
        return view;
    }

    if (buffer.size() < view.size()) {
        buffer.resize(view.size());
    } else {
        // view & buffer might overlap in memory,
        // so we avoid shrinking the buffer prior to the memmove
    }

    // view & buffer might overlap in memory,
    // thus memmove instead of memcpy
    std::memmove(buffer.data(), view.data(), view.size());

    assert(view.size() < min_size);
    buffer.resize(view.size());
    buffer.resize(min_size);

    return buffer;
}

evmc::address to_address(ByteView bytes) {
    evmc::address out;
    if (!bytes.empty()) {
        size_t n{std::min(bytes.length(), kAddressLength)};
        std::memcpy(out.bytes + kAddressLength - n, bytes.data(), n);
    }
    return out;
}

evmc::bytes32 to_bytes32(ByteView bytes) {
    evmc::bytes32 out;
    if (!bytes.empty()) {
        size_t n{std::min(bytes.length(), kHashLength)};
        std::memcpy(out.bytes + kHashLength - n, bytes.data(), n);
    }
    return out;
}

ByteView zeroless_view(const ByteView& data) {
    return data.substr(static_cast<size_t>(std::distance(
        data.begin(), as_range::find_if_not(data, [](const auto& b) { return b == 0x0; }))));
}

ByteView zeroless_view(const evmc::bytes32& hash) { return zeroless_view(full_view(hash)); }

std::string to_hex(const evmc::address& address) { return to_hex(full_view(address)); }

std::string to_hex(const evmc::bytes32& hash) { return to_hex(full_view(hash)); }

std::string to_hex(ByteView bytes) {
    static const char* kHexDigits{"0123456789abcdef"};
    std::string out(bytes.length() * 2, '\0');
    char* dest{&out[0]};
    for (const auto& b : bytes) {
        *dest++ = kHexDigits[b >> 4];    // Hi
        *dest++ = kHexDigits[b & 0x0f];  // Lo
    }
    return out;
}

static inline uint8_t unhex_lut(uint8_t x) { return kUnhexTable[x]; }
static inline uint8_t unhex_lut4(uint8_t x) { return kUnhexTable4[x]; }

std::optional<unsigned> decode_hex_digit(char ch) noexcept {
    auto ret{unhex_lut(static_cast<uint8_t>(ch))};
    if (ret == 0xbc) {
        return std::nullopt;
    }
    return ret;
}

std::optional<Bytes> from_hex(std::string_view hex) noexcept {
    if (hex.length() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex.remove_prefix(2);
    }
    if (hex.empty()) {
        return Bytes{};
    }

    size_t pos(hex.length() & 1);  // "[0x]1" is legit and has to be treated as "[0x]01"
    Bytes out((hex.length() + pos) / 2, '\0');
    char* src{const_cast<char*>(hex.data())};
    uint8_t* dst{&out[0]};

    if (pos) {
        auto b{unhex_lut(static_cast<uint8_t>(*src++))};
        if (b == 0xbc) {
            return std::nullopt;
        }
        *dst++ = b;
    }

    for (; pos < out.length(); ++pos) {
        auto a{unhex_lut4(static_cast<uint8_t>(*src++))};
        auto b{unhex_lut(static_cast<uint8_t>(*src++))};
        if (a == 0xbc || b == 0xbc) {
            return std::nullopt;
        }
        *dst++ = a | b;
    }
    return out;
}

inline bool case_insensitive_char_comparer(char a, char b) { return (tolower(a) == tolower(b)); }

bool iequals(const std::string& a, const std::string& b) {
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

std::string human_size(uint64_t bytes) {
    static const char* suffix[]{"B", "KB", "MB", "GB", "TB"};
    static const uint32_t items{sizeof(suffix) / sizeof(suffix[0])};
    uint32_t index{0};
    double value{static_cast<double>(bytes)};
    while (value >= kKibi) {
        value /= kKibi;
        if (++index == (items - 1)) {
            break;
        }
    }
    static char output[64];
    sprintf(output, "%.02lf %s", value, suffix[index]);
    return std::string(output);
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

std::vector<std::string> split(std::string_view source, std::string_view delimiter) {
    std::vector<std::string> res{};
    if (delimiter.length() >= source.length() || !delimiter.length()) {
        res.emplace_back(source);
        return res;
    }
    size_t pos{0};
    while ((pos = source.find(delimiter)) != std::string::npos) {
        res.emplace_back(source.substr(0, pos));
        source.remove_prefix(pos + delimiter.length());
    }
    // Any residual part of input where delimiter is not found
    if (source.length()) {
        res.emplace_back(source);
    }
    return res;
}

}  // namespace silkworm
