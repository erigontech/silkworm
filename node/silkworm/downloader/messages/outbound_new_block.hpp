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

#include <silkworm/downloader/internals/header_chain.hpp>
#include <silkworm/downloader/packets/new_block_packet.hpp>

#include "outbound_message.hpp"

namespace silkworm {

class OutboundNewBlock : public OutboundMessage {
  public:
    OutboundNewBlock();

    std::string name() const override { return "OutboundNewBlock"; }
    std::string content() const override;

    void execute(db::ROAccess, HeaderChain&, BodySequence&, SentryClient&) override;

  private:
    sentry::SentPeers send_packet(SentryClient& sentry, const NewBlockPacket& packet, seconds_t timeout);

    static constexpr uint64_t kMaxPeers = 1024;

    long sent_packets_{0};
    // NewBlockPacket packet_;
};

}  // namespace silkworm
