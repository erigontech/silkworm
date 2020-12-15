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

#include "util.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <iterator>
#include <regex>

namespace silkworm {

ByteView left_pad(ByteView view, size_t min_size) {
    if (view.size() >= min_size) {
        return view;
    }

    thread_local Bytes padded;

    if (padded.size() < min_size) {
        padded.resize(min_size);
    }

    assert(view.size() < min_size);
    size_t prefix_len{min_size - view.size()};

    std::memmove(padded.data() + prefix_len, view.data(), view.size());

    padded.resize(min_size);
    std::fill_n(padded.data(), prefix_len, '\0');

    return padded;
}

ByteView right_pad(ByteView view, size_t min_size) {
    if (view.size() >= min_size) {
        return view;
    }

    thread_local Bytes padded;

    if (padded.size() < view.size()) {
        padded.resize(view.size());
    }

    std::memmove(padded.data(), view.data(), view.size());

    assert(view.size() < min_size);
    padded.resize(view.size());
    padded.resize(min_size);

    return padded;
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

static unsigned decode_hex_digit(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    } else if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    } else if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    throw std::out_of_range{"not a hex digit"};
}

Bytes from_hex(std::string_view hex) {
    if (hex.length() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex.remove_prefix(2);
    }

    assert(hex.length() % 2 == 0);

    Bytes out{};
    out.reserve(hex.length() / 2);

    unsigned carry{0};
    for (size_t i{0}; i < hex.size(); ++i) {
        unsigned v{decode_hex_digit(hex[i])};
        if (i % 2 == 0) {
            carry = v << 4;
        } else {
            out.push_back(static_cast<uint8_t>(carry | v));
        }
    }

    return out;
}

std::optional<size_t> parse_size(const std::string& sizestr) {
    if (sizestr.empty()) {
        return 0;
    }

    static const std::regex pattern{"^([0-9]{1,})([\\ ]{0,})?(B|KB|MB|GB|TB)?$"};
    std::smatch matches;
    if (!std::regex_search(sizestr, matches, pattern, std::regex_constants::match_default)) {
        return std::nullopt;
    };

    uint64_t number{std::strtoull(matches[1].str().c_str(), nullptr, 10)};

    if (matches[3].length() == 0) {
        return number;
    }
    std::string suffix = matches[3].str();
    if (suffix == "B") {
        return number;
    } else if (suffix == "KB") {
        return number * kKibi;
    } else if (suffix == "MB") {
        return number * kMebi;
    } else if (suffix == "GB") {
        return number * kGibi;
    } else if (suffix == "TB") {
        return number * kTebi;
    } else {
        return std::nullopt;
    }
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
}  // namespace silkworm
