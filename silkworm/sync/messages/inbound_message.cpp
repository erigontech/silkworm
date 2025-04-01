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

#include "inbound_message.hpp"

namespace silkworm {

std::ostream& operator<<(std::ostream& os, const silkworm::InboundMessage& msg) {
    os << msg.to_string();
    return os;
}

std::string InboundMessage::to_string() const {
    const auto& msg = *this;
    std::stringstream os;

    os << msg.name() << " content: " << msg.content();
    return os.str();
}

std::string identify(const silkworm::InboundMessage& message) {
    return message.name() + " reqId=" + std::to_string(message.req_id());
}

}  // namespace silkworm
