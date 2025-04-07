// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/sync/internals/types.hpp>
#include <silkworm/sync/packets/new_block_hashes_packet.hpp>

#include "inbound_message.hpp"

namespace silkworm {

class InboundNewBlockHashes : public InboundMessage {
  public:
    InboundNewBlockHashes(ByteView data, PeerId peer_id);

    std::string name() const override { return "InboundNewBlockHashes"; }
    std::string content() const override;
    uint64_t req_id() const override;

    void execute(db::DataStoreRef, HeaderChain&, BodySequence&, SentryClient&) override;

  private:
    PeerId peer_id_;
    NewBlockHashesPacket packet_;
    uint64_t req_id_;
};

}  // namespace silkworm
