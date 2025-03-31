// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "find_node_message.hpp"

#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/unix_timestamp.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/packet_type.hpp>

namespace silkworm::sentry::discovery::disc_v4::find {

const uint8_t FindNodeMessage::kId = static_cast<uint8_t>(PacketType::kFindNode);

Bytes FindNodeMessage::rlp_encode() const {
    Bytes data;
    auto expiration_ts = unix_timestamp_from_time_point(expiration);
    rlp::encode(data, target_public_key.serialized(), expiration_ts);
    return data;
}

FindNodeMessage FindNodeMessage::rlp_decode(ByteView data) {
    Bytes target_public_key_data;
    uint64_t expiration_ts{0};

    auto result = rlp::decode(
        data,
        rlp::Leftover::kAllow,
        target_public_key_data,
        expiration_ts);
    if (!result && (result.error() != DecodingError::kUnexpectedListElements)) {
        throw DecodingException(result.error(), "Failed to decode FindNodeMessage RLP");
    }

    auto target_public_key = [&target_public_key_data]() -> EccPublicKey {
        try {
            return EccPublicKey::deserialize(target_public_key_data);
        } catch (const std::runtime_error& ex) {
            throw DecodeTargetPublicKeyError(ex);
        }
    }();

    return FindNodeMessage{
        std::move(target_public_key),
        time_point_from_unix_timestamp(expiration_ts),
    };
}

}  // namespace silkworm::sentry::discovery::disc_v4::find
