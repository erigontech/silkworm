// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::sentry::discovery::disc_v4::enr {

struct EnrRequestMessage {
    std::chrono::time_point<std::chrono::system_clock> expiration;

    Bytes rlp_encode() const;
    static EnrRequestMessage rlp_decode(ByteView data);

    static const uint8_t kId;
};

}  // namespace silkworm::sentry::discovery::disc_v4::enr
