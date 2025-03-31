// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace silkworm::sentry::rlpx::crypto {

Bytes sha256(ByteView data);

}  // namespace silkworm::sentry::rlpx::crypto
