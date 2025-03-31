// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "inbound_message.hpp"

namespace silkworm {

std::ostream& operator<<(std::ostream& os, const silkworm::InboundMessage& msg) {
    os << msg.name() << " content: " << msg.content();
    return os;
}

std::string identify(const silkworm::InboundMessage& message) {
    return message.name() + " reqId=" + std::to_string(message.req_id());
}

}  // namespace silkworm
