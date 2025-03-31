// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <vector>

#include <silkworm/sync/packets/get_block_headers_packet.hpp>

#include "outbound_message.hpp"

namespace silkworm {

class OutboundGetBlockHeaders : public OutboundMessage {
  public:
    OutboundGetBlockHeaders() = default;
    explicit OutboundGetBlockHeaders(GetBlockHeadersPacket66 packet) : packet_(packet) {}

    std::string name() const override { return "OutboundGetBlockHeaders"; }
    std::string content() const override;

    void execute(db::DataStoreRef, HeaderChain&, BodySequence&, SentryClient&) override;

    silkworm::sentry::eth::MessageId eth_message_id() const override {
        return silkworm::sentry::eth::MessageId::kGetBlockHeaders;
    }

    Bytes message_data() const override;

    GetBlockHeadersPacket66& packet();
    std::vector<PeerPenalization>& penalties();
    bool packet_present() const;

  private:
    std::vector<PeerId> send_packet(SentryClient&);

    GetBlockHeadersPacket66 packet_{};
    std::vector<PeerPenalization> penalizations_;
};

}  // namespace silkworm
