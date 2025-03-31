// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "endian.hpp"

#include <silkworm/core/common/util.hpp>

namespace silkworm::endian {

ByteView to_big_compact(const uint64_t value) {
    if (!value) {
        return {};
    }
    SILKWORM_THREAD_LOCAL uint8_t full_be[sizeof(uint64_t)];
    store_big_u64(&full_be[0], value);
    return zeroless_view(full_be);
}

ByteView to_big_compact(const intx::uint256& value) {
    if (!value) {
        return {};
    }
    SILKWORM_THREAD_LOCAL uint8_t full_be[sizeof(intx::uint256)];
    intx::be::store(full_be, value);
    return zeroless_view(full_be);
}

}  // namespace silkworm::endian
