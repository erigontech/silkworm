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

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <silkworm/common/base.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/rpc/server/wait_strategy.hpp>
#include <silkworm/sentry/common/enode_url.hpp>

#include "nat_option.hpp"

struct buildinfo;

namespace silkworm::sentry {

struct Settings {
    const buildinfo* build_info{nullptr};
    log::Settings log_settings;

    std::string api_address{"127.0.0.1:9091"};

    // RLPx TCP port
    uint16_t port{30303};

    NatOption nat;

    // initialized in the constructor based on hardware_concurrency
    uint32_t num_contexts{0};

    silkworm::rpc::WaitMode wait_mode{silkworm::rpc::WaitMode::blocking};

    std::filesystem::path data_dir_path;

    std::optional<std::variant<std::filesystem::path, Bytes>> node_key;

    std::vector<common::EnodeUrl> static_peers;

    Settings();
};

}  // namespace silkworm::sentry
