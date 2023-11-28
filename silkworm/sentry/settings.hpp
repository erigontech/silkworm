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

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/context_pool_settings.hpp>
#include <silkworm/sentry/common/enode_url.hpp>

#include "nat/nat_option.hpp"

struct buildinfo;

namespace silkworm::sentry {

struct Settings {
    std::string client_id{"silkworm"};
    log::Settings log_settings;

    std::string api_address{"127.0.0.1:9091"};

    // RLPx TCP port and disc v4 UDP port
    uint16_t port{30303};

    nat::NatOption nat;

    // Settings for the GRPC server context pool
    concurrency::ContextPoolSettings context_pool_settings;

    std::filesystem::path data_dir_path;

    uint64_t network_id{1};

    std::optional<std::variant<std::filesystem::path, Bytes>> node_key;

    std::vector<EnodeUrl> static_peers;
    std::vector<EnodeUrl> bootnodes;

    bool no_discover{false};

    size_t max_peers{100};
};

}  // namespace silkworm::sentry
