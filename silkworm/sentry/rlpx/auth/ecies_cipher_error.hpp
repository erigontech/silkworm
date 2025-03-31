// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/sentry/common/error.hpp>

namespace silkworm::sentry::rlpx::auth {

enum class EciesCipherErrorCode : uint8_t {
    kSharedSecretFailure = 1,
    kInvalidMAC,
    kDataSizeTooShort,
};

using EciesCipherError = sentry::Error<EciesCipherErrorCode>;

}  // namespace silkworm::sentry::rlpx::auth
