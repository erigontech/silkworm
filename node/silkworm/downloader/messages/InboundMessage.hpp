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

#ifndef SILKWORM_INBOUNDMESSAGE_HPP
#define SILKWORM_INBOUNDMESSAGE_HPP

#include <memory>

#include <silkworm/downloader/internals/db_tx.hpp>
#include <silkworm/downloader/internals/working_chain.hpp>
#include <silkworm/downloader/sentry_client.hpp>
#include <silkworm/rlp/decode.hpp>
#include <silkworm/rlp/encode.hpp>

#include "Message.hpp"

namespace silkworm {

class InboundMessage : public Message {
  public:
    void execute() override = 0;

    virtual uint64_t reqId() const = 0;
    virtual std::string content() const = 0;
};

std::ostream& operator<<(std::ostream&, const silkworm::InboundMessage&);
std::string identify(const silkworm::InboundMessage& message);

struct InboundBlockRequestMessage : public InboundMessage {
    static std::shared_ptr<InboundMessage> make(const sentry::InboundMessage& msg, Db::ReadOnlyAccess db,
                                                SentryClient& sentry);
};

struct InboundBlockAnnouncementMessage : public InboundMessage {
    static std::shared_ptr<InboundMessage> make(const sentry::InboundMessage& msg, WorkingChain& wc,
                                                SentryClient& sentry);
};

}  // namespace silkworm

#endif  // SILKWORM_INBOUNDMESSAGE_HPP
