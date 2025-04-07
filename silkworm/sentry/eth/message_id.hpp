// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>

namespace silkworm::sentry::eth {

enum class MessageId : uint8_t {
    kStatus = 0x00,
    kNewBlockHashes = 0x01,
    kTransactions = 0x02,
    kGetBlockHeaders = 0x03,
    kBlockHeaders = 0x04,
    kGetBlockBodies = 0x05,
    kBlockBodies = 0x06,
    kNewBlock = 0x07,
    kNewPooledTransactionHashes = 0x08,
    kGetPooledTransactions = 0x09,
    kPooledTransactions = 0x0A,
    kGetNodeData = 0x0D,  // removed in eth/67
    kNodeData = 0x0E,     // removed in eth/67
    kGetReceipts = 0x0F,
    kReceipts = 0x10,
};

MessageId eth_message_id_from_common_id(uint8_t id);
uint8_t common_message_id_from_eth_id(MessageId eth_id);

}  // namespace silkworm::sentry::eth
