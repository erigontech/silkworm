// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
