// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "pong_message.hpp"

#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/unix_timestamp.hpp>
#include <silkworm/sentry/discovery/common/node_address.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/packet_type.hpp>

namespace silkworm::sentry::discovery::disc_v4::ping {

const uint8_t PongMessage::kId = static_cast<uint8_t>(PacketType::kPong);

Bytes PongMessage::rlp_encode() const {
    Bytes data;
    NodeAddress recipient_address{recipient_endpoint, 0};
    auto expiration_ts = unix_timestamp_from_time_point(expiration);
    auto enr_seq_num_value = enr_seq_num ? *enr_seq_num : 0;
    rlp::encode(data, recipient_address, ping_hash, expiration_ts, enr_seq_num_value);
    return data;
}

PongMessage PongMessage::rlp_decode(ByteView data) {
    NodeAddress recipient_address;
    Bytes ping_hash;
    uint64_t expiration_ts{0};
    std::optional<uint64_t> enr_seq_num_opt;

    auto result = rlp::decode(
        data,
        rlp::Leftover::kAllow,
        recipient_address,
        ping_hash,
        expiration_ts);
    if (!result && (result.error() != DecodingError::kUnexpectedListElements)) {
        throw DecodingException(result.error(), "Failed to decode PingMessage RLP");
    }

    uint64_t enr_seq_num{0};
    if (rlp::decode(data, enr_seq_num)) {
        enr_seq_num_opt = enr_seq_num;
    }

    return PongMessage{
        std::move(recipient_address.endpoint),
        std::move(ping_hash),
        time_point_from_unix_timestamp(expiration_ts),
        enr_seq_num_opt,
    };
}

}  // namespace silkworm::sentry::discovery::disc_v4::ping