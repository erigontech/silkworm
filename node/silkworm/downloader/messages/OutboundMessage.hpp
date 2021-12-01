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
#ifndef SILKWORM_OUTBOUNDMESSAGE_HPP
#define SILKWORM_OUTBOUNDMESSAGE_HPP

#include "Message.hpp"
#include <silkworm/downloader/sentry_client.hpp>

namespace silkworm {

class OutboundMessage : public Message {
  public:
    void execute() override = 0;

    virtual std::string content() const = 0;
};

inline std::ostream& operator<<(std::ostream& os, const silkworm::OutboundMessage& msg) {
    os << msg.name() << " content: " << msg.content();
    return os;
}

}  // namespace silkworm
#endif  // SILKWORM_OUTBOUNDMESSAGE_HPP
