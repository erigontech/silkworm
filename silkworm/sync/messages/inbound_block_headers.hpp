// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/sync/internals/types.hpp>
#include <silkworm/sync/packets/block_headers_packet.hpp>

#include "inbound_message.hpp"

namespace silkworm {

class InboundBlockHeaders : public InboundMessage {
  public:
    InboundBlockHeaders(ByteView data, PeerId peer_id);

    std::string name() const override { return "InboundBlockHeaders"; }
    std::string content() const override;
    uint64_t req_id() const override;

    void execute(db::DataStoreRef, HeaderChain&, BodySequence&, SentryClient&) override;

  private:
    PeerId peer_id_;
    BlockHeadersPacket66 packet_;
};

}  // namespace silkworm
