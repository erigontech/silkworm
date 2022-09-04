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

#include <memory>

#include <silkworm/rlp/decode.hpp>
#include <silkworm/rlp/encode.hpp>

#include "message.hpp"

namespace silkworm {

class InboundMessage : public Message {
  public:
    static std::shared_ptr<InboundMessage> make(const sentry::InboundMessage& msg);

    void execute(db::ROAccess, HeaderChain&, BodySequence&, SentryClient&) override = 0;

    virtual uint64_t reqId() const = 0;
    virtual std::string content() const = 0;
};

std::ostream& operator<<(std::ostream&, const silkworm::InboundMessage&);
std::string identify(const silkworm::InboundMessage& message);

}  // namespace silkworm
