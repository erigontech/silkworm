// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "hex.hpp"

#include <optional>
#include <stdexcept>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkworm::test_util {

std::string ascii_from_hex(std::string_view hex) {
    const std::optional<Bytes> bytes{from_hex(hex)};
    if (!bytes) {
        throw std::runtime_error{"ascii_from_hex"};
    }
    return std::string{byte_view_to_string_view(*bytes)};
}

}  // namespace silkworm::test_util
