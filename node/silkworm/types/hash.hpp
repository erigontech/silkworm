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

#include <silkworm/common/assert.hpp>
#include <silkworm/common/base.hpp>
#include <silkworm/common/util.hpp>

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

    std::string to_hex() { return silkworm::to_hex(*this); }
    static Hash from_hex(const std::string& hex) { return {evmc::from_hex<Hash>(hex).value()}; }

    // conversion to ByteView is handled in ByteView class,
    // conversion operator Byte() { return {bytes, length()}; } is handled elsewhere

    static_assert(sizeof(evmc::bytes32) == 32);
};

}  // namespace silkworm
