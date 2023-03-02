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

#include "send_message_to_random_peers.hpp"

namespace silkworm::rpc {

SendMessageToRandomPeers::SendMessageToRandomPeers(uint64_t max_peers, std::unique_ptr<sentry::OutboundMessageData> message)
    : UnaryCall("SendMessageToRandomPeers", &sentry::Sentry::Stub::SendMessageToRandomPeers, {}) {
    request_.set_max_peers(max_peers);
    request_.set_allocated_data(message.release());  // take ownership
}

}  // namespace silkworm::rpc