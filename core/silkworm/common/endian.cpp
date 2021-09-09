/*
   Copyright 2021 The Silkworm Authors

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

#include "endian.hpp"

#include <silkworm/common/util.hpp>

namespace silkworm::endian {

Bytes to_big_compact(const uint64_t value) {
    SILKWORM_THREAD_LOCAL uint8_t full_be[sizeof(uint64_t)];
    store_big_u64(&full_be[0], value);
    return Bytes{zeroless_view(full_be)};
}

Bytes to_big_compact(const intx::uint256& value) {
    SILKWORM_THREAD_LOCAL uint8_t full_be[sizeof(intx::uint256)];
    intx::be::store(full_be, value);
    return Bytes{zeroless_view(full_be)};
}

template <typename T>
static std::optional<T> from_big_compact(const ByteView& data, bool allow_leading_zeros) {
    if (data.length() > sizeof(T)) {
        return std::nullopt;
    }

    T x{0};

    if (data.empty()) {
        return x;
    }

    if (data[0] == 0 && !allow_leading_zeros) {
        return std::nullopt;
    }

    auto* ptr{reinterpret_cast<uint8_t*>(&x)};
    std::memcpy(ptr + (sizeof(T) - data.length()), &data[0], data.length());

#if SILKWORM_BYTE_ORDER == SILKWORM_LITTLE_ENDIAN
    x = intx::bswap(x);
#endif

    return x;
}

std::optional<uint64_t> from_big_compact_u64(const ByteView& data, bool allow_leading_zeros) {
    return from_big_compact<uint64_t>(data, allow_leading_zeros);
}

std::optional<intx::uint256> from_big_compact_u256(const ByteView& data, bool allow_leading_zeros) {
    return from_big_compact<intx::uint256>(data, allow_leading_zeros);
}

}  // namespace silkworm::endian
