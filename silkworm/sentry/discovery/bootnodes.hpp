// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <span>

#include <silkworm/sentry/common/enode_url.hpp>

namespace silkworm::sentry::discovery {

std::span<EnodeUrl> bootnodes(uint64_t network_id);

}  // namespace silkworm::sentry::discovery
