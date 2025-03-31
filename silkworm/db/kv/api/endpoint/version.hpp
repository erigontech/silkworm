// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <tuple>

namespace silkworm::db::kv::api {

using Version = std::tuple<uint32_t, uint32_t, uint32_t>;

//! Current KV API protocol version.
inline constexpr Version kCurrentVersion{5, 1, 0};

}  // namespace silkworm::db::kv::api
