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

#ifndef SILKWORM_TYPES_BLOOM_HPP_
#define SILKWORM_TYPES_BLOOM_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <silkworm/types/log.hpp>

namespace silkworm {

constexpr size_t kBloomByteLength{256};
constexpr size_t kBloomU64Length{kBloomByteLength / sizeof(uint64_t)};

using Bloom     = std::array<uint8_t,   kBloomByteLength>;
using Bloom_u64 = std::array<uint64_t,  kBloomU64Length>;

inline ByteView full_view(const Bloom& bloom) { return {bloom.data(), kBloomByteLength}; }

Bloom logs_bloom(const std::vector<Log>& logs);

inline void join(Bloom& sum, const Bloom& addend) {
    Bloom_u64& sum_u64 = *(reinterpret_cast<Bloom_u64 *>(&sum));
    const Bloom_u64& addend_u64 = *(reinterpret_cast<const Bloom_u64 *>(&addend));

    for (size_t i{0}; i < kBloomU64Length; ++i) {
        sum_u64[i] |= addend_u64[i];
    }
}

inline bool operator==(const Bloom& a, const Bloom& b) {
    return std::memcmp(&a[0], &b[0], kBloomByteLength) == 0;
}

inline bool operator!=(const Bloom& a, const Bloom& b) {
    return std::memcmp(&a[0], &b[0], kBloomByteLength) != 0;
}

}  // namespace silkworm

#endif  // SILKWORM_TYPES_BLOOM_HPP_
