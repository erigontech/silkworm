// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/sync/packets/block_headers_packet.hpp>

#include "outbound_message.hpp"

namespace silkworm {

class OutboundBlockHeaders : public OutboundMessage {
  public:
    explicit OutboundBlockHeaders(BlockHeadersPacket66 packet) : packet_(std::move(packet)) {}

    std::string name() const override { return "OutboundBlockHeaders"; }
    std::string content() const override;

    void execute(db::DataStoreRef, HeaderChain&, BodySequence&, SentryClient&) override;

    silkworm::sentry::eth::MessageId eth_message_id() const override {
        return silkworm::sentry::eth::MessageId::kBlockHeaders;
    }

    Bytes message_data() const override;

  private:
    BlockHeadersPacket66 packet_{};
};

}  // namespace silkworm
