// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "environment.hpp"

#include <boost/process/environment.hpp>

namespace silkworm {

std::optional<BlockNum> Environment::get_stop_at_block() {
    std::optional<BlockNum> target_block;
    // User can specify to stop downloading process at some block
    auto environment = boost::this_process::environment();
    auto stop_at_block = environment["STOP_AT_BLOCK"];
    if (!stop_at_block.empty()) {
        target_block = std::stoul(stop_at_block.to_string());
    }
    return target_block;
}

void Environment::set_stop_at_block(BlockNum block_num) {
    auto environment = boost::this_process::environment();
    environment["STOP_AT_BLOCK"] = std::to_string(block_num);
}

std::optional<std::string> Environment::get_start_at_stage() {
    std::optional<std::string> stage;
    // User can specify to start staged execution at some stage
    auto environment = boost::this_process::environment();
    auto start_at_stage = environment["START_AT_STAGE"];
    if (!start_at_stage.empty()) {
        stage = start_at_stage.to_string();
    }
    return stage;
}

void Environment::set_start_at_stage(std::string_view stage_name) {
    auto environment = boost::this_process::environment();
    environment["START_AT_STAGE"] = std::string{stage_name};
}

std::optional<std::string> Environment::get_stop_before_stage() {
    std::optional<std::string> stage;
    // User can specify to stop staged execution before some stage
    auto environment = boost::this_process::environment();
    auto stop_before_stage = environment["STOP_BEFORE_STAGE"];
    if (!stop_before_stage.empty()) {
        stage = stop_before_stage.to_string();
    }
    return stage;
}

void Environment::set_stop_before_stage(std::string_view stage_name) {
    auto environment = boost::this_process::environment();
    environment["STOP_BEFORE_STAGE"] = std::string{stage_name};
}

bool Environment::are_pre_verified_hashes_disabled() {
    bool disabled = false;
    // User can specify to not use the pre-verified hashes and do a full header verification
    auto environment = boost::this_process::environment();
    auto env_var = environment["DISABLE_PRE_VERIFIED_HASHES"];
    if (!env_var.empty()) {
        disabled = std::stoul(env_var.to_string()) != 0;
    }
    return disabled;
}

void Environment::set_pre_verified_hashes_disabled() {
    auto environment = boost::this_process::environment();
    environment["DISABLE_PRE_VERIFIED_HASHES"] = "1";
}

std::string Environment::get(std::string_view var_name) {
    auto environment = boost::this_process::environment();
    const auto env_var = environment[std::string{var_name}];
    return env_var.to_string();
}

}  // namespace silkworm