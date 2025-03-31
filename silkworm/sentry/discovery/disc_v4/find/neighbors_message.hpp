// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>
#include <map>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/discovery/common/node_address.hpp>

namespace silkworm::sentry::discovery::disc_v4::find {

struct NeighborsMessage {
    std::map<EccPublicKey, NodeAddress> node_addresses;
    std::chrono::time_point<std::chrono::system_clock> expiration;

    Bytes rlp_encode() const;
    static NeighborsMessage rlp_decode(ByteView data);

    static const uint8_t kId;
};

}  // namespace silkworm::sentry::discovery::disc_v4::find
