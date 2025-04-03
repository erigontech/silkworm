// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/message.hpp>

namespace silkworm::sentry::rlpx {

struct PingMessage {
    Bytes rlp_encode() const;
    sentry::Message to_message() const;
    static const uint8_t kId;
};

struct PongMessage {
    Bytes rlp_encode() const;
    sentry::Message to_message() const;
    static const uint8_t kId;
};

}  // namespace silkworm::sentry::rlpx
