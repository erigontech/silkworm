// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string_view>
#include <vector>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkworm::rpc {

inline void deserialize_hex_as_bytes(std::string_view hex, std::vector<Bytes>& sequence) {
    auto bytes{from_hex(hex)};
    if (bytes) {
        sequence.push_back(std::move(*bytes));
    }
}

}  // namespace silkworm::rpc
