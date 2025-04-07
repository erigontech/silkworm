// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "xor.hpp"

#include <algorithm>
#include <functional>

namespace silkworm::sentry::crypto {

void xor_bytes(Bytes& data1, ByteView data2) {
    SILKWORM_ASSERT(data1.size() <= data2.size());
    std::transform(data1.cbegin(), data1.cend(), data2.cbegin(), data1.begin(), std::bit_xor<>{});
}

}  // namespace silkworm::sentry::crypto
