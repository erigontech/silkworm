// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <vector>

#include <silkworm/sync/packets/get_block_bodies_packet.hpp>

#include "outbound_message.hpp"

namespace silkworm {

class OutboundGetBlockBodies : public OutboundMessage {
  public:
    OutboundGetBlockBodies() = default;

    std::string name() const override { return "OutboundGetBlockBodies"; }
    std::string content() const override;

    void execute(db::DataStoreRef, HeaderChain&, BodySequence&, SentryClient&) override;

    silkworm::sentry::eth::MessageId eth_message_id() const override {
        return silkworm::sentry::eth::MessageId::kGetBlockBodies;
    }

    Bytes message_data() const override;

    GetBlockBodiesPacket66& packet();
    std::vector<PeerPenalization>& penalties();
    BlockNum& min_block();

    bool packet_present() const;

  private:
    std::vector<PeerId> send_packet(SentryClient&);

    GetBlockBodiesPacket66 packet_{};
    std::vector<PeerPenalization> penalizations_;
    BlockNum min_block_{0};
};

}  // namespace silkworm
