/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_OUTBOUNDGETBLOCKHEADERS_HPP
#define SILKWORM_OUTBOUNDGETBLOCKHEADERS_HPP

#include <silkworm/downloader/internals/working_chain.hpp>
#include <silkworm/downloader/packets/GetBlockHeadersPacket.hpp>

#include "OutboundMessage.hpp"

namespace silkworm {

class OutboundGetBlockHeaders : public OutboundMessage {
  public:
    OutboundGetBlockHeaders(WorkingChain&, SentryClient&);

    std::string name() const override { return "OutboundGetBlockHeaders"; }
    std::string content() const override;

    void execute() override;  // headers_forward function in Erigon

    int sent_request();

  private:
    sentry::SentPeers send_packet(const GetBlockHeadersPacket66&, seconds_t timeout);
    void send_penalization(const PeerPenalization&, seconds_t timeout);

    int sent_reqs_{0};
    std::string packets_;
    WorkingChain& working_chain_;
    SentryClient& sentry_;
};

}  // namespace silkworm
#endif  // SILKWORM_OUTBOUNDGETBLOCKHEADERS_HPP
