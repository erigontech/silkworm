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

#include <silkworm/rlp/decode.hpp>
#include <silkworm/rlp/encode.hpp>

#include <silkworm/downloader/DbTx.hpp>

#include "Message.hpp"


namespace silkworm {


class InboundMessage : public Message {
  public:
    using reply_call_t = rpc_t; // a more specific name
    using reply_calls_t = rpc_bundle_t;

    reply_calls_t execute() override = 0;
};

class InboundBlockRequestMessage : public InboundMessage {
  public:
    static std::shared_ptr<InboundMessage> make_from_raw_message(const sentry::InboundMessage& msg, DbTx& db);
};

std::ostream& operator<<(std::ostream&, const silkworm::InboundMessage&);

}

#endif  // SILKWORM_INBOUNDMESSAGE_HPP
