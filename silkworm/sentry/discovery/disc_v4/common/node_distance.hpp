// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::discovery::disc_v4 {

size_t node_distance(const EccPublicKey& id1, const EccPublicKey& id2);

}  // namespace silkworm::sentry::discovery::disc_v4
