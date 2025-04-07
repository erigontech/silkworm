// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/interfaces/p2psentry/sentry.grpc.pb.h>
#include <silkworm/sentry/api/common/message_id_set.hpp>
#include <silkworm/sentry/common/message.hpp>

namespace silkworm::sentry::grpc::interfaces {

sentry::Message message_from_outbound_data(const ::sentry::OutboundMessageData& message_data);
::sentry::OutboundMessageData outbound_data_from_message(const sentry::Message& message);

sentry::Message message_from_inbound_message(const ::sentry::InboundMessage& message);
::sentry::InboundMessage inbound_message_from_message(const sentry::Message& message);

uint8_t message_id_from_proto_message_id(::sentry::MessageId proto_id);
::sentry::MessageId proto_message_id_from_message_id(uint8_t message_id);

api::MessageIdSet message_id_set_from_messages_request(const ::sentry::MessagesRequest& request);
::sentry::MessagesRequest messages_request_from_message_id_set(const api::MessageIdSet& message_ids);

}  // namespace silkworm::sentry::grpc::interfaces
