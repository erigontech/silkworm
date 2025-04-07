// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/hash.hpp>

namespace silkworm::execution::api {

struct Body : public BlockBody {
    Hash block_hash;
    BlockNum block_num{0};
};

}  // namespace silkworm::execution::api
