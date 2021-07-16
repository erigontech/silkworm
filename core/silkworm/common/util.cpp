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

#include <cassert>
#include <regex>

namespace silkworm {

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
    size_t n{std::min(bytes.length(), kAddressLength)};
    std::memcpy(out.bytes + kAddressLength - n, bytes.data(), n);
    return out;
}

evmc::bytes32 to_bytes32(ByteView bytes) {
    evmc::bytes32 out;
    size_t n{std::min(bytes.length(), kHashLength)};
    std::memcpy(out.bytes + kHashLength - n, bytes.data(), n);
    return out;
}

ByteView zeroless_view(const evmc::bytes32& hash) {
    unsigned zero_bytes{0};
    while (zero_bytes < kHashLength && hash.bytes[zero_bytes] == 0) {
        ++zero_bytes;
    }
    return {hash.bytes + zero_bytes, kHashLength - zero_bytes};
}

std::string to_hex(const evmc::address& address) { return to_hex(full_view(address)); }

std::string to_hex(const evmc::bytes32& hash) { return to_hex(full_view(hash)); }

std::string to_hex(ByteView bytes) {
    static const char* kHexDigits{"0123456789abcdef"};

    std::string out{};
    out.reserve(2 * bytes.length());

    for (size_t i{0}; i < bytes.length(); ++i) {
        uint8_t x{bytes[i]};
        char lo{kHexDigits[x & 0x0f]};
        char hi{kHexDigits[x >> 4]};
        out.push_back(hi);
        out.push_back(lo);
    }

    return out;
}

static std::optional<unsigned> decode_hex_digit(char ch) noexcept {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    } else if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    } else if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return std::nullopt;
}

std::optional<Bytes> from_hex(std::string_view hex) noexcept {
    if (hex.length() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex.remove_prefix(2);
    }

    if (hex.length() % 2 != 0) {
        return std::nullopt;
    }

    Bytes out{};
    out.reserve(hex.length() / 2);

    unsigned carry{0};
    for (size_t i{0}; i < hex.size(); ++i) {
        std::optional<unsigned> v{decode_hex_digit(hex[i])};
        if (!v) {
            return std::nullopt;
        }
        if (i % 2 == 0) {
            carry = *v << 4;
        } else {
            out.push_back(static_cast<uint8_t>(carry | *v));
        }
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
    };

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
        // Use literals so we don't deal with floats and doubles
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

std::vector<std::string> split(std::string source, std::string delimiter) {
    std::vector<std::string> res{};
    if (delimiter.length() >= source.length() || !delimiter.length()) {
        res.emplace_back(source);
        return res;
    }
    size_t pos{0};
    while ((pos = source.find(delimiter)) != std::string::npos) {
        res.emplace_back(source.substr(0, pos));
        source.erase(0, pos + delimiter.length());
    }
    // Any residual part of input where delimiter is not found
    if (source.length()) {
        res.emplace_back(source);
    }
    return res;
}

}  // namespace silkworm
