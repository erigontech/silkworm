/*
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#pragma once

#include <silkworm/downloader/packets/get_block_bodies_packet.hpp>

#include "outbound_message.hpp"

namespace silkworm {

class OutboundGetBlockBodies : public OutboundMessage {
  public:
    OutboundGetBlockBodies(size_t max_reqs, uint64_t active_peers);

    std::string name() const override { return "OutboundGetBlockBodies"; }
    std::string content() const override;

    void execute(db::ROAccess, HeaderChain&, BodySequence&, SentryClient&) override;

    size_t sent_requests() const;
    size_t nack_requests() const;

  private:
    sentry::SentPeers send_packet(SentryClient&, const GetBlockBodiesPacket66&, BlockNum min_block, seconds_t timeout);
    void send_penalization(SentryClient&, const PeerPenalization&, seconds_t timeout);

    size_t max_reqs_;
    size_t sent_reqs_{0};
    size_t nack_reqs_{0};
    size_t requested_bodies_{0};
    uint64_t active_peers_;
};

}  // namespace silkworm
