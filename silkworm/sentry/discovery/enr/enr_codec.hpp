// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>

#include "enr_record.hpp"

namespace silkworm::sentry::discovery::enr {

struct EnrCodec {
    static EnrRecord decode(ByteView data);
    static Bytes encode(const EnrRecord& record, const EccKeyPair& key_pair);
};

}  // namespace silkworm::sentry::discovery::enr
