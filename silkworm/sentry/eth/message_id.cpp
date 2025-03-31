// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "message_id.hpp"

#include "status_message.hpp"

namespace silkworm::sentry::eth {

MessageId eth_message_id_from_common_id(uint8_t message_id) {
    SILKWORM_ASSERT(message_id >= eth::StatusMessage::kId);
    if (message_id < eth::StatusMessage::kId)
        return MessageId::kStatus;

    return static_cast<eth::MessageId>(message_id - eth::StatusMessage::kId);
}

uint8_t common_message_id_from_eth_id(MessageId eth_id) {
    return (static_cast<uint8_t>(eth_id) + eth::StatusMessage::kId);
}

}  // namespace silkworm::sentry::eth
