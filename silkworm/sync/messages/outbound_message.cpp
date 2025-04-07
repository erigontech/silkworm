// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "outbound_message.hpp"

namespace silkworm {

size_t OutboundMessage::sent_requests() const { return sent_reqs_; }
size_t OutboundMessage::nack_requests() const { return nack_reqs_; }

}  // namespace silkworm