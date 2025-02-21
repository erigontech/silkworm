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

// The most common and basic macros, concepts, types, and constants.

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <tuple>

#include <intx/intx.hpp>

#include <silkworm/core/common/assert.hpp>

#if defined(__wasm__)
#define SILKWORM_THREAD_LOCAL static
#else
#define SILKWORM_THREAD_LOCAL thread_local
#endif

namespace silkworm {

using namespace std::string_view_literals;

template <class T>
concept UnsignedIntegral = std::unsigned_integral<T> || std::same_as<T, intx::uint128> ||
                           std::same_as<T, intx::uint256> || std::same_as<T, intx::uint512>;

using TxnId = uint64_t;

inline constexpr TxnId kMaxTxnId = std::numeric_limits<TxnId>::max();

struct TxnIdRange {
    TxnId start;
    TxnId end;
    TxnIdRange(TxnId start1, TxnId end1) : start(start1), end(end1) {}
    friend bool operator==(const TxnIdRange&, const TxnIdRange&) = default;
    bool contains(TxnId num) const { return (start <= num) && (num < end); }
    bool contains_range(TxnIdRange range) const { return (start <= range.start) && (range.end <= end); }
    TxnId size() const { return end - start; }
    std::string to_string() const { return std::string("[") + std::to_string(start) + ", " + std::to_string(end) + ")"; }
};

using BlockNum = uint64_t;

inline constexpr BlockNum kMaxBlockNum = std::numeric_limits<BlockNum>::max();

struct BlockNumRange {
    BlockNum start;
    BlockNum end;
    BlockNumRange(BlockNum start1, BlockNum end1) : start(start1), end(end1) {}
    friend bool operator==(const BlockNumRange&, const BlockNumRange&) = default;
    bool contains(BlockNum block_num) const { return (start <= block_num) && (block_num < end); }
    bool contains_range(BlockNumRange range) const { return (start <= range.start) && (range.end <= end); }
    BlockNum size() const { return end - start; }
    std::string to_string() const { return std::string("[") + std::to_string(start) + ", " + std::to_string(end) + ")"; }
};

using BlockTime = uint64_t;

inline constexpr BlockNum kEarliestBlockNum{0ul};

inline constexpr size_t kAddressLength{20};

inline constexpr size_t kHashLength{32};

// https://en.wikipedia.org/wiki/Binary_prefix
inline constexpr uint64_t kKibi{1024};
inline constexpr uint64_t kMebi{1024 * kKibi};
inline constexpr uint64_t kGibi{1024 * kMebi};
inline constexpr uint64_t kTebi{1024 * kGibi};

inline constexpr uint64_t kGiga{1'000'000'000};   // = 10^9
inline constexpr uint64_t kEther{kGiga * kGiga};  // = 10^18

consteval uint64_t operator"" _Kibi(unsigned long long x) {
    SILKWORM_ASSERT(x <= std::numeric_limits<uint64_t>::max() / kKibi);
    return x * kKibi;
}
consteval uint64_t operator"" _Mebi(unsigned long long x) {
    SILKWORM_ASSERT(x <= std::numeric_limits<uint64_t>::max() / kMebi);
    return x * kMebi;
}
consteval uint64_t operator"" _Gibi(unsigned long long x) {
    SILKWORM_ASSERT(x <= std::numeric_limits<uint64_t>::max() / kGibi);
    return x * kGibi;
}
consteval uint64_t operator"" _Tebi(unsigned long long x) {
    SILKWORM_ASSERT(x <= std::numeric_limits<uint64_t>::max() / kTebi);
    return x * kTebi;
}

}  // namespace silkworm
