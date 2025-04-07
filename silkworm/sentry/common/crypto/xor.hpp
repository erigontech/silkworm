// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace silkworm::sentry::crypto {

void xor_bytes(Bytes& data1, ByteView data2);

}  // namespace silkworm::sentry::crypto
