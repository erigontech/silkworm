// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <vector>

#include <silkworm/core/common/base.hpp>

#include "status_message.hpp"

namespace silkworm::sentry::eth {

struct StatusData {
    std::vector<BlockNum> fork_block_nums;
    std::vector<BlockTime> fork_block_times;
    BlockNum head_block_num{0};
    StatusMessage message;
};

}  // namespace silkworm::sentry::eth
