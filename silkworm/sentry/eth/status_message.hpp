// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/message.hpp>

#include "fork_id.hpp"

namespace silkworm::sentry::eth {

struct StatusMessage {
    Bytes rlp_encode() const;
    static StatusMessage rlp_decode(ByteView data);

    Message to_message() const;
    static StatusMessage from_message(const Message& message);

    uint8_t version{0};
    uint64_t network_id{0};
    intx::uint256 total_difficulty;
    Bytes best_block_hash;
    Bytes genesis_hash;
    ForkId fork_id;

    static const uint8_t kId;
};

}  // namespace silkworm::sentry::eth
