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

#include <string>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/decode.hpp>

namespace silkworm {

class Hash : public evmc::bytes32 {
  public:
    using evmc::bytes32::bytes32;

    Hash() = default;
    explicit Hash(ByteView bv) {
        std::memcpy(bytes, bv.data(), length());
        SILKWORM_ASSERT(bv.length() == length());
    }

    static constexpr size_t length() { return sizeof(evmc::bytes32); }

    [[nodiscard]] std::string to_hex() const { return silkworm::to_hex(*this); }
    static Hash from_hex(const std::string& hex) { return {evmc::from_hex<Hash>(hex).value()}; }

    // conversion to ByteView is handled in ByteView class,
    // conversion operator Byte() { return {bytes, length()}; } is handled elsewhere

    static_assert(sizeof(evmc::bytes32) == 32);
};

// RLP encoding: usually same as ByteView, some tricks for MSVC overload resolution
namespace rlp {
    inline size_t length_hash(const Hash&) { return kHashLength + 1; }

    void encode_hash(Bytes& to, const Hash& h);

    // template <>
    DecodingResult decode_hash(ByteView& from, Hash& to) noexcept;

}  // namespace rlp

}  // namespace silkworm

namespace std {

template <>
struct hash<silkworm::Hash> : public std::hash<evmc::bytes32>  // to use Hash with std::unordered_set/map
{};

}  // namespace std
