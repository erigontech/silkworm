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

#include "pong_message.hpp"

#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/unix_timestamp.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/node_address.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/packet_type.hpp>

namespace silkworm::sentry::discovery::disc_v4::ping {

const uint8_t PongMessage::kId = static_cast<uint8_t>(PacketType::kPong);

Bytes PongMessage::rlp_encode() const {
    Bytes data;
    NodeAddress recipient_address{recipient_endpoint, 0};
    auto expiration_ts = unix_timestamp_from_time_point(expiration);
    rlp::encode(data, recipient_address, ping_hash, expiration_ts);
    return data;
}

PongMessage PongMessage::rlp_decode(ByteView data) {
    NodeAddress recipient_address;
    Bytes ping_hash;
    uint64_t expiration_ts;

    auto result = rlp::decode(
        data,
        rlp::Leftover::kAllow,
        recipient_address,
        ping_hash,
        expiration_ts);
    if (!result && (result.error() != DecodingError::kUnexpectedListElements)) {
        throw DecodingException(result.error(), "Failed to decode PingMessage RLP");
    }

    return PongMessage{
        std::move(recipient_address.endpoint),
        std::move(ping_hash),
        time_point_from_unix_timestamp(expiration_ts),
    };
}

}  // namespace silkworm::sentry::discovery::disc_v4::ping