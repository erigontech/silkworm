// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdexcept>
#include <string>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/discovery/enr/enr_record.hpp>

namespace silkworm::sentry::discovery::disc_v4::enr {

struct EnrResponseMessage {
    using EnrRecord = discovery::enr::EnrRecord;

    Bytes request_hash;
    EnrRecord record;

    Bytes rlp_encode(const EccKeyPair& key_pair) const;
    static EnrResponseMessage rlp_decode(ByteView data);

    static const uint8_t kId;

    class DecodeEnrRecordError : public std::runtime_error {
      public:
        explicit DecodeEnrRecordError(const std::exception& ex)
            : std::runtime_error(std::string("Failed to decode EnrResponseMessage.record: ") + ex.what()) {}
    };
};

}  // namespace silkworm::sentry::discovery::disc_v4::enr
