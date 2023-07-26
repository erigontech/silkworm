/*
   Copyright 2023 The Silkworm Authors

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

#include "ping_message.hpp"

#include <silkworm/core/rlp/encode_vector.hpp>

namespace silkworm::sentry::rlpx {

const uint8_t PingMessage::kId = 2;
const uint8_t PongMessage::kId = 3;

Bytes PingMessage::rlp_encode() const {
    Bytes data;
    rlp::encode(data, std::vector<uint8_t>{});
    return data;
}

Bytes PongMessage::rlp_encode() const {
    Bytes data;
    rlp::encode(data, std::vector<uint8_t>{});
    return data;
}

sentry::Message PingMessage::to_message() const {
    return sentry::Message{kId, rlp_encode()};
}

sentry::Message PongMessage::to_message() const {
    return sentry::Message{kId, rlp_encode()};
}

}  // namespace silkworm::sentry::rlpx
