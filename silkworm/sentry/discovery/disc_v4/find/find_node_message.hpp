// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>
#include <string>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::discovery::disc_v4::find {

struct FindNodeMessage {
    EccPublicKey target_public_key;
    std::chrono::time_point<std::chrono::system_clock> expiration;

    Bytes rlp_encode() const;
    static FindNodeMessage rlp_decode(ByteView data);

    static const uint8_t kId;

    class DecodeTargetPublicKeyError : public std::runtime_error {
      public:
        explicit DecodeTargetPublicKeyError(const std::exception& ex)
            : std::runtime_error(std::string("Failed to decode FindNodeMessage.target_public_key: ") + ex.what()) {}
    };
};

}  // namespace silkworm::sentry::discovery::disc_v4::find
