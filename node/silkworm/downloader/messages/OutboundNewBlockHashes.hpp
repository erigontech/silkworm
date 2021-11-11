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

#ifndef SILKWORM_OUTBOUNDNEWBLOCKHASHES_HPP
#define SILKWORM_OUTBOUNDNEWBLOCKHASHES_HPP

#include <silkworm/downloader/internals/working_chain.hpp>
#include <silkworm/downloader/packets/NewBlockHashesPacket.hpp>

#include "OutboundMessage.hpp"

namespace silkworm {

class OutboundNewBlockHashes : public OutboundMessage {
  public:
    OutboundNewBlockHashes(WorkingChain&, SentryClient&);

    std::string name() const override { return "OutboundNewBlockHashes"; }
    std::string content() const override;

    void execute() override;

  private:
    NewBlockHashesPacket packet_;
    WorkingChain& working_chain_;
    SentryClient& sentry_;
};

}  // namespace silkworm
#endif  // SILKWORM_OUTBOUNDNEWBLOCKHASHES_HPP
