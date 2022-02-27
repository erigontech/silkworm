/*
   Copyright 2020-2022 The Silkworm Authors

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

#include "bloom.hpp"

#include <ethash/keccak.hpp>

#include <silkworm/common/util.hpp>

namespace silkworm {

void Bloom::add(const Bloom& addend) {
    for (size_t i{0}; i < kBloomByteLength; ++i) {
        (*this)[i] |= addend[i];
    }
}

void Bloom::m3_2048(gsl::span<const uint8_t, kHashLength> hash) {
    for (unsigned i{0}; i < 6; i += 2) {
        unsigned bit{static_cast<unsigned>(hash[i + 1] + (hash[i] << 8)) & 0x7FFu};
        (*this)[kBloomByteLength - 1 - bit / 8] |= 1 << (bit % 8);
    }
}

Bloom LogsBloomer::bloom_filter(const std::vector<Log>& logs) {
    Bloom bloom;
    for (const Log& log : logs) {
        bloom.m3_2048(keccak256(log.address).bytes);
        for (const auto& topic : log.topics) {
            bloom.m3_2048(keccak256(topic).bytes);
        }
    }
    return bloom;
}

namespace rlp {
    template <>
    DecodingResult decode(ByteView& from, Bloom& to) noexcept {
        return decode(from, static_cast<std::array<uint8_t, kBloomByteLength>&>(to));
    }
}  // namespace rlp

}  // namespace silkworm
