// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/sync/packets/block_bodies_packet.hpp>

#include "outbound_message.hpp"

namespace silkworm {

class OutboundBlockBodies : public OutboundMessage {
  public:
    explicit OutboundBlockBodies(BlockBodiesPacket66 packet) : packet_(std::move(packet)) {}

    std::string name() const override { return "OutboundBlockBodies"; }
    std::string content() const override;

    void execute(db::DataStoreRef, HeaderChain&, BodySequence&, SentryClient&) override;

    silkworm::sentry::eth::MessageId eth_message_id() const override {
        return silkworm::sentry::eth::MessageId::kBlockBodies;
    }

    Bytes message_data() const override;

  private:
    BlockBodiesPacket66 packet_{};
};

}  // namespace silkworm
