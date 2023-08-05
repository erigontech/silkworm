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

#include "disconnect_message.hpp"

#include <stdexcept>
#include <vector>

#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>

namespace silkworm::sentry::rlpx {

using sentry::Message;

const uint8_t DisconnectMessage::kId = 1;

Bytes DisconnectMessage::rlp_encode() const {
    Bytes data;
    rlp::encode(data, std::vector<uint8_t>{static_cast<uint8_t>(reason)});
    return data;
}

DisconnectMessage DisconnectMessage::rlp_decode(ByteView data) {
    if (data.empty()) {
        return DisconnectMessage{};
    }

    std::vector<uint8_t> reason;
    auto result = rlp::decode(data, reason);

    // if RLP is not a list
    if (!result && (result.error() == DecodingError::kUnexpectedString)) {
        uint8_t reason_num;
        result = rlp::decode(data, reason_num);
        if (result) {
            reason.push_back(reason_num);
        }
    }

    if (!result) {
        throw DecodingException(result.error(), "Failed to decode DisconnectMessage RLP");
    }

    DisconnectMessage message;
    if (!reason.empty()) {
        message.reason = static_cast<DisconnectReason>(reason.front());
    }
    return message;
}

Message DisconnectMessage::to_message() const {
    return Message{kId, rlp_encode()};
}

DisconnectMessage DisconnectMessage::from_message(const Message& message) {
    return rlp_decode(message.data);
}

}  // namespace silkworm::sentry::rlpx
