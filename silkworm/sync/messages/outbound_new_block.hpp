// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <vector>

#include <silkworm/sync/internals/body_sequence.hpp>
#include <silkworm/sync/packets/new_block_packet.hpp>

#include "outbound_message.hpp"

namespace silkworm {

class OutboundNewBlock : public OutboundMessage {
  public:
    OutboundNewBlock(Blocks, bool is_first_sync);

    std::string name() const override { return "OutboundNewBlock"; }
    std::string content() const override;

    void execute(db::DataStoreRef, HeaderChain&, BodySequence&, SentryClient&) override;

    silkworm::sentry::eth::MessageId eth_message_id() const override {
        return silkworm::sentry::eth::MessageId::kNewBlock;
    }

    Bytes message_data() const override;

  private:
    std::vector<PeerId> send_packet(SentryClient& sentry, NewBlockPacket packet);

    static constexpr uint64_t kMaxPeers = 1024;

    int64_t sent_packets_{0};
    Blocks blocks_to_announce_;
    bool is_first_sync_;
    NewBlockPacket packet_;
};

}  // namespace silkworm
