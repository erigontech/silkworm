// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <variant>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/hash.hpp>

namespace silkworm::execution::api {

using BlockNumOrHash = std::variant<BlockNum, Hash>;

}  // namespace silkworm::execution::api
