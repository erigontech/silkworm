// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/message.hpp>

namespace silkworm::sentry::discovery::disc_v4 {

struct MessageEnvelope {
    Message message;
    EccPublicKey public_key;
    Bytes packet_hash;
};

struct MessageCodec {
    static Bytes encode(const Message& message, ByteView private_key);
    static ByteView encoded_packet_hash(ByteView packet_data);
    static MessageEnvelope decode(ByteView packet_data);
};

}  // namespace silkworm::sentry::discovery::disc_v4
