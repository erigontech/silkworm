// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/sync/packets/new_block_hashes_packet.hpp>

#include "outbound_message.hpp"

namespace silkworm {

class OutboundNewBlockHashes : public OutboundMessage {
  public:
    explicit OutboundNewBlockHashes(bool is_first_sync);

    std::string name() const override { return "OutboundNewBlockHashes"; }
    std::string content() const override;

    void execute(db::DataStoreRef, HeaderChain&, BodySequence&, SentryClient&) override;

    silkworm::sentry::eth::MessageId eth_message_id() const override {
        return silkworm::sentry::eth::MessageId::kNewBlockHashes;
    }

    Bytes message_data() const override;

  private:
    NewBlockHashesPacket packet_;
    bool is_first_sync_;
};

}  // namespace silkworm
