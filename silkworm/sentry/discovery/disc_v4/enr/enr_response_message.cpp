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

#include "enr_response_message.hpp"

#include <vector>

#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/packet_type.hpp>
#include <silkworm/sentry/discovery/enr/enr_codec.hpp>

namespace silkworm::sentry::discovery::disc_v4::enr {

const uint8_t EnrResponseMessage::kId = static_cast<uint8_t>(PacketType::kEnrResponse);

Bytes EnrResponseMessage::rlp_encode(const EccKeyPair& key_pair) const {
    Bytes request_hash_rlp_data;
    rlp::encode(request_hash_rlp_data, request_hash);

    std::vector<rlp::RlpBytes> items = {
        rlp::RlpBytes{request_hash_rlp_data},
        rlp::RlpBytes{discovery::enr::EnrCodec::encode(record, key_pair)},
    };

    Bytes data;
    rlp::encode(data, items);
    return data;
}

EnrResponseMessage EnrResponseMessage::rlp_decode(ByteView data) {
    auto rlp_header = rlp::decode_header(data);
    if (!rlp_header)
        throw DecodingException(rlp_header.error(), "Failed to decode EnrResponseMessage RLP header");
    if (!rlp_header->list)
        throw DecodingException(DecodingError::kUnexpectedString, "Failed to decode EnrResponseMessage RLP");

    Bytes request_hash;
    auto request_hash_decode_result = rlp::decode(data, request_hash, rlp::Leftover::kAllow);
    if (!request_hash_decode_result)
        throw DecodingException(request_hash_decode_result.error(), "Failed to decode EnrResponseMessage RLP request_hash");

    ByteView enr_data = data;
    auto record = [&enr_data]() -> discovery::enr::EnrRecord {
        try {
            return discovery::enr::EnrCodec::decode(enr_data);
        } catch (const std::runtime_error& ex) {
            throw DecodeEnrRecordError(ex);
        }
    }();

    return EnrResponseMessage{
        std::move(request_hash),
        std::move(record),
    };
}

}  // namespace silkworm::sentry::discovery::disc_v4::enr
