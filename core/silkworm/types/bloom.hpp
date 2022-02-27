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

#ifndef SILKWORM_TYPES_BLOOM_HPP_
#define SILKWORM_TYPES_BLOOM_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <gsl/span>

#include <silkworm/rlp/decode.hpp>
#include <silkworm/types/log.hpp>

namespace silkworm {

inline constexpr size_t kBloomByteLength{256};

// See Section 4.3.1 "Transaction Receipt" of the Yellow Paper
class Bloom : public std::array<uint8_t, kBloomByteLength> {
  public:
    // zero initialization
    Bloom() noexcept : std::array<uint8_t, kBloomByteLength>{} {}

    void add(const Bloom& addend);

    void m3_2048(gsl::span<const uint8_t, kHashLength> hash);
};

class LogsBloomer {
  public:
    // Not copyable nor movable
    LogsBloomer(const LogsBloomer&) = delete;
    LogsBloomer& operator=(const LogsBloomer&) = delete;

    LogsBloomer() noexcept = default;

    virtual ~LogsBloomer() = default;

    // Bloom filter function, M, to reduce a log entry into a single 256-byte hash.
    // See YP, Section 4.3.1. "Transaction Receipt"
    virtual Bloom bloom_filter(const std::vector<Log>& logs);
};

namespace rlp {
    template <>
    DecodingResult decode(ByteView& from, Bloom& to) noexcept;
}  // namespace rlp

}  // namespace silkworm

#endif  // SILKWORM_TYPES_BLOOM_HPP_
