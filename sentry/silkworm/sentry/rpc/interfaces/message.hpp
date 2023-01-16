/*
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#pragma once

#include <p2psentry/sentry.grpc.pb.h>

#include <silkworm/sentry/common/message.hpp>

namespace silkworm::sentry::rpc::interfaces {

sentry::common::Message message_from_outbound_data(const ::sentry::OutboundMessageData& message_data);

::sentry::InboundMessage inbound_message_from_message(const sentry::common::Message& message);

uint8_t message_id(::sentry::MessageId proto_id);

}  // namespace silkworm::sentry::rpc::interfaces
