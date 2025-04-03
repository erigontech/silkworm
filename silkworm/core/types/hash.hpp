// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <span>
#include <string>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/decode.hpp>

namespace silkworm {

class Hash : public evmc::bytes32 {
  public:
    using evmc::bytes32::bytes32;

    Hash() = default;
    explicit Hash(ByteView bv) {
        std::memcpy(bytes, bv.data(), size());
        SILKWORM_ASSERT(bv.size() == size());
    }

    static constexpr size_t size() { return sizeof(evmc::bytes32); }

    std::string to_hex() const { return silkworm::to_hex(*this); }
    static std::optional<Hash> from_hex(const std::string& hex) { return evmc::from_hex<Hash>(hex); }

    // conversion to ByteView
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    operator ByteView() const { return ByteView{bytes}; }

    static_assert(sizeof(evmc::bytes32) == 32);
};

using HashAsSpan = std::span<const uint8_t, kHashLength>;
using HashAsArray = const uint8_t (&)[kHashLength];

namespace rlp {
    inline DecodingResult decode(ByteView& from, Hash& to, Leftover mode = Leftover::kProhibit) {
        return decode(from, to.bytes, mode);
    }
}  // namespace rlp

}  // namespace silkworm

namespace std {

template <>
struct hash<silkworm::Hash> : public std::hash<evmc::bytes32>  // to use Hash with std::unordered_set/map
{};

}  // namespace std
