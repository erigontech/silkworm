// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "outbound_block_headers.hpp"

#include <sstream>

#include <silkworm/infra/common/log.hpp>

namespace silkworm {

void OutboundBlockHeaders::execute(db::DataStoreRef, HeaderChain&, BodySequence&, SentryClient&) {
}

Bytes OutboundBlockHeaders::message_data() const {
    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, packet_);
    return rlp_encoding;
}

std::string OutboundBlockHeaders::content() const {
    std::stringstream content;
    log::prepare_for_logging(content);
    content << packet_;
    return content.str();
}

}  // namespace silkworm
