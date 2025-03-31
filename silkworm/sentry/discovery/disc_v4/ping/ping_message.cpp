// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ping_message.hpp"

#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/unix_timestamp.hpp>
#include <silkworm/sentry/discovery/common/node_address.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/packet_type.hpp>

namespace silkworm::sentry::discovery::disc_v4::ping {

const uint8_t PingMessage::kId = static_cast<uint8_t>(PacketType::kPing);

Bytes PingMessage::rlp_encode() const {
    Bytes data;
    constexpr int kDiscVersion = 4;
    NodeAddress sender_address{sender_endpoint, sender_port_rlpx};
    NodeAddress recipient_address{recipient_endpoint, 0};
    auto expiration_ts = unix_timestamp_from_time_point(expiration);
    auto enr_seq_num_value = enr_seq_num ? *enr_seq_num : 0;
    rlp::encode(data, kDiscVersion, sender_address, recipient_address, expiration_ts, enr_seq_num_value);
    return data;
}

PingMessage PingMessage::rlp_decode(ByteView data) {
    unsigned int disc_version{0};
    NodeAddress sender_address;
    NodeAddress recipient_address;
    uint64_t expiration_ts{0};
    std::optional<uint64_t> enr_seq_num_opt;

    auto result = rlp::decode(
        data,
        rlp::Leftover::kAllow,
        disc_version,
        sender_address,
        recipient_address,
        expiration_ts);
    if (!result && (result.error() != DecodingError::kUnexpectedListElements)) {
        throw DecodingException(result.error(), "Failed to decode PingMessage RLP");
    }

    uint64_t enr_seq_num{0};
    if (rlp::decode(data, enr_seq_num)) {
        enr_seq_num_opt = enr_seq_num;
    }

    return PingMessage{
        std::move(sender_address.endpoint),
        sender_address.port_rlpx,
        std::move(recipient_address.endpoint),
        time_point_from_unix_timestamp(expiration_ts),
        enr_seq_num_opt,
    };
}

}  // namespace silkworm::sentry::discovery::disc_v4::ping