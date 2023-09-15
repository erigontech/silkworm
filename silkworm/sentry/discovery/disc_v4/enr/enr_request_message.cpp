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

#include "enr_request_message.hpp"

#include <vector>

#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/unix_timestamp.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/packet_type.hpp>

namespace silkworm::sentry::discovery::disc_v4::enr {

const uint8_t EnrRequestMessage::kId = static_cast<uint8_t>(PacketType::kEnrRequest);

Bytes EnrRequestMessage::rlp_encode() const {
    Bytes data;
    auto expiration_ts = unix_timestamp_from_time_point(expiration);
    rlp::encode(data, std::vector<uint64_t>{expiration_ts});
    return data;
}

EnrRequestMessage EnrRequestMessage::rlp_decode(ByteView data) {
    std::vector<uint64_t> expiration_ts;

    auto result = rlp::decode(
        data,
        expiration_ts,
        rlp::Leftover::kAllow);
    if (!result && (result.error() != DecodingError::kUnexpectedListElements)) {
        throw DecodingException(result.error(), "Failed to decode EnrRequestMessage RLP");
    }
    if (expiration_ts.empty()) {
        throw DecodingException(DecodingError::kUnexpectedListElements, "Failed to decode EnrRequestMessage RLP: no expiration");
    }

    return EnrRequestMessage{
        time_point_from_unix_timestamp(expiration_ts[0]),
    };
}

}  // namespace silkworm::sentry::discovery::disc_v4::enr
