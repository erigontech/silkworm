// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>
#include <vector>

namespace silkworm::rpc {

struct StageData {
    std::string stage_name;
    std::string block_num;
};

struct SyncingData {
    std::string current_block;
    std::string max_block;
    std::vector<StageData> stages;
};

}  // namespace silkworm::rpc
