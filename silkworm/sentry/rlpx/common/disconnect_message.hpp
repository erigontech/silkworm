// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/message.hpp>

#include "disconnect_reason.hpp"

namespace silkworm::sentry::rlpx {

struct DisconnectMessage {
    Bytes rlp_encode() const;
    static DisconnectMessage rlp_decode(ByteView data);

    sentry::Message to_message() const;
    static DisconnectMessage from_message(const sentry::Message& message);

    static const uint8_t kId;
    DisconnectReason reason{DisconnectReason::kDisconnectRequested};
};

}  // namespace silkworm::sentry::rlpx
