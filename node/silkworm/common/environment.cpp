/*
Copyright 2022 The Silkworm Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "environment.hpp"

#include <boost/process/environment.hpp>

namespace silkworm {

std::optional<BlockNum> Environment::get_stop_at_block() {
    std::optional<BlockNum> target_block;
    // User can specify to stop downloading process at some block
    if (const char* stop_at_block{std::getenv("STOP_AT_BLOCK")}; stop_at_block != nullptr) {
        target_block = std::stoul(stop_at_block);
    }
    return target_block;
}

void Environment::set_stop_at_block(BlockNum block_num) {
    auto environment = boost::this_process::environment();
    environment["STOP_AT_BLOCK"] = std::to_string(block_num);
}

std::optional<std::string> Environment::get_stop_before_stage() {
    std::optional<std::string> stop_before_stage;
    // User can specify to stop staged execution before some stage
    if (const char* stop_stage_name{std::getenv("STOP_BEFORE_STAGE")}; stop_stage_name != nullptr) {
        stop_before_stage = stop_stage_name;
    }
    return stop_before_stage;
}

void Environment::set_stop_before_stage(std::string stage_name) {
    auto environment = boost::this_process::environment();
    environment["STOP_BEFORE_STAGE"] = stage_name;
}

bool Environment::are_pre_verified_hashes_disabled() {
    bool disabled = false;
    // User can specify to not use the pre-verified hashes and do a full header verification
    const char* env_var{std::getenv("DISABLE_PRE_VERIFIED_HASHES")};
    if (env_var != nullptr) {
        disabled = std::stoul(env_var) != 0;
    }
    return disabled;
}

void Environment::set_pre_verified_hashes_disabled() {
    auto environment = boost::this_process::environment();
    environment["DISABLE_PRE_VERIFIED_HASHES"] = "1";
}

}