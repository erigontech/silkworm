// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace silkworm::sentry::rlpx::crypto {

Bytes hmac(ByteView key, ByteView data1, ByteView data2, ByteView data3);

}  // namespace silkworm::sentry::rlpx::crypto
