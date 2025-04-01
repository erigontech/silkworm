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

#include <ostream>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/eth/message_id.hpp>

#include "message.hpp"

namespace silkworm {

class OutboundMessage : public Message {
  public:
    void execute(db::DataStoreRef, HeaderChain&, BodySequence&, SentryClient&) override = 0;

    size_t sent_requests() const;
    size_t nack_requests() const;

    virtual std::string content() const = 0;

    virtual silkworm::sentry::eth::MessageId eth_message_id() const = 0;
    virtual Bytes message_data() const = 0;
    virtual std::string to_string() const;

  protected:
    size_t sent_reqs_{0};
    size_t nack_reqs_{0};
};

inline std::ostream& operator<<(std::ostream& os, const silkworm::OutboundMessage& msg) {
    os << msg.to_string();
    return os;
}

inline std::string OutboundMessage::to_string() const {
    const auto& msg = *this;
    std::stringstream os;

    os << msg.name() << " content: " << msg.content();
    return os.str();
}

}  // namespace silkworm
