// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "message.hpp"

#include <optional>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/sentry/eth/message_id.hpp>
#include <silkworm/sentry/eth/status_message.hpp>

namespace silkworm::sentry::grpc::interfaces {

namespace proto = ::sentry;

static std::optional<eth::MessageId> eth_message_id(proto::MessageId proto_id) {
    switch (proto_id) {
        case proto::STATUS_66:
            return eth::MessageId::kStatus;
        case proto::NEW_BLOCK_HASHES_66:
            return eth::MessageId::kNewBlockHashes;
        case proto::NEW_BLOCK_66:
            return eth::MessageId::kNewBlock;
        case proto::TRANSACTIONS_66:
            return eth::MessageId::kTransactions;
        case proto::NEW_POOLED_TRANSACTION_HASHES_66:
        case proto::NEW_POOLED_TRANSACTION_HASHES_68:
            return eth::MessageId::kNewPooledTransactionHashes;
        case proto::GET_BLOCK_HEADERS_66:
            return eth::MessageId::kGetBlockHeaders;
        case proto::GET_BLOCK_BODIES_66:
            return eth::MessageId::kGetBlockBodies;
        case proto::GET_NODE_DATA_66:
            return eth::MessageId::kGetNodeData;
        case proto::GET_RECEIPTS_66:
            return eth::MessageId::kGetReceipts;
        case proto::GET_POOLED_TRANSACTIONS_66:
            return eth::MessageId::kGetPooledTransactions;
        case proto::BLOCK_HEADERS_66:
            return eth::MessageId::kBlockHeaders;
        case proto::BLOCK_BODIES_66:
            return eth::MessageId::kBlockBodies;
        case proto::NODE_DATA_66:
            return eth::MessageId::kNodeData;
        case proto::RECEIPTS_66:
            return eth::MessageId::kReceipts;
        case proto::POOLED_TRANSACTIONS_66:
            return eth::MessageId::kPooledTransactions;
        default:
            return std::nullopt;
    }
}

static proto::MessageId proto_message_id_from_eth_id(eth::MessageId eth_id) {
    switch (eth_id) {
        case eth::MessageId::kStatus:
            return proto::STATUS_66;
        case eth::MessageId::kNewBlockHashes:
            return proto::NEW_BLOCK_HASHES_66;
        case eth::MessageId::kNewBlock:
            return proto::NEW_BLOCK_66;
        case eth::MessageId::kTransactions:
            return proto::TRANSACTIONS_66;
        case eth::MessageId::kNewPooledTransactionHashes:
            return proto::NEW_POOLED_TRANSACTION_HASHES_68;
        case eth::MessageId::kGetBlockHeaders:
            return proto::GET_BLOCK_HEADERS_66;
        case eth::MessageId::kGetBlockBodies:
            return proto::GET_BLOCK_BODIES_66;
        case eth::MessageId::kGetNodeData:
            return proto::GET_NODE_DATA_66;
        case eth::MessageId::kGetReceipts:
            return proto::GET_RECEIPTS_66;
        case eth::MessageId::kGetPooledTransactions:
            return proto::GET_POOLED_TRANSACTIONS_66;
        case eth::MessageId::kBlockHeaders:
            return proto::BLOCK_HEADERS_66;
        case eth::MessageId::kBlockBodies:
            return proto::BLOCK_BODIES_66;
        case eth::MessageId::kNodeData:
            return proto::NODE_DATA_66;
        case eth::MessageId::kReceipts:
            return proto::RECEIPTS_66;
        case eth::MessageId::kPooledTransactions:
            return proto::POOLED_TRANSACTIONS_66;
        default:
            SILKWORM_ASSERT(false);
            return proto::STATUS_66;
    }
}

uint8_t message_id_from_proto_message_id(proto::MessageId proto_id) {
    auto eth_id = eth_message_id(proto_id);
    SILKWORM_ASSERT(eth_id.has_value());
    if (!eth_id)
        return eth::StatusMessage::kId;

    return eth::common_message_id_from_eth_id(eth_id.value());
}

proto::MessageId proto_message_id_from_message_id(uint8_t message_id) {
    return proto_message_id_from_eth_id(eth::eth_message_id_from_common_id(message_id));
}

sentry::Message message_from_outbound_data(const proto::OutboundMessageData& message_data) {
    return {
        message_id_from_proto_message_id(message_data.id()),
        Bytes{string_view_to_byte_view(message_data.data())},
    };
}

proto::OutboundMessageData outbound_data_from_message(const sentry::Message& message) {
    proto::OutboundMessageData result;
    result.set_id(proto_message_id_from_message_id(message.id));
    result.set_data(message.data.data(), message.data.size());
    return result;
}

sentry::Message message_from_inbound_message(const ::sentry::InboundMessage& message_data) {
    return {
        message_id_from_proto_message_id(message_data.id()),
        Bytes{string_view_to_byte_view(message_data.data())},
    };
}

proto::InboundMessage inbound_message_from_message(const sentry::Message& message) {
    proto::InboundMessage result;
    result.set_id(proto_message_id_from_message_id(message.id));
    result.set_data(message.data.data(), message.data.size());
    return result;
}

api::MessageIdSet message_id_set_from_messages_request(const proto::MessagesRequest& request) {
    api::MessageIdSet filter;
    for (int i = 0; i < request.ids_size(); ++i) {
        auto id = request.ids(i);
        filter.insert(message_id_from_proto_message_id(id));
    }
    return filter;
}

proto::MessagesRequest messages_request_from_message_id_set(const api::MessageIdSet& message_ids) {
    proto::MessagesRequest result;
    for (auto id : message_ids) {
        result.add_ids(proto_message_id_from_message_id(id));
    }
    return result;
}

}  // namespace silkworm::sentry::grpc::interfaces
