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

#include <silkworm/sync/internals/types.hpp>
#include <silkworm/sync/packets/new_block_packet.hpp>

#include "inbound_message.hpp"

namespace silkworm {

class InboundNewBlock : public InboundMessage {
  public:
    InboundNewBlock(ByteView data, PeerId peer_id);

    std::string name() const override { return "InboundNewBlock"; }
    std::string content() const override;
    uint64_t req_id() const override;

    void execute(db::DataStoreRef, HeaderChain&, BodySequence&, SentryClient&) override;

  private:
    PeerId peer_id_;
    NewBlockPacket packet_;
    uint64_t req_id_;
};

}  // namespace silkworm
