// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <silkworm/core/common/base.hpp>

namespace silkworm {

class Environment {
  public:
    static std::optional<BlockNum> get_stop_at_block();
    static void set_stop_at_block(BlockNum block_num);

    static std::optional<std::string> get_start_at_stage();
    static void set_start_at_stage(std::string_view stage_name);

    static std::optional<std::string> get_stop_before_stage();
    static void set_stop_before_stage(std::string_view stage_name);

    static bool are_pre_verified_hashes_disabled();
    static void set_pre_verified_hashes_disabled();

    static std::string get(std::string_view var_name);
};

}  // namespace silkworm