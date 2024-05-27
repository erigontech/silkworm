/*
   Copyright 2023 The Silkworm Authors

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

#include <optional>
#include <string>
#include <vector>

#include <silkworm/infra/common/application_info.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/context_pool_settings.hpp>
#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/common/interface_log.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>

namespace silkworm::rpc {

struct DaemonSettings {
    ApplicationInfo build_info;
    log::Settings log_settings;
    InterfaceLogSettings eth_ifc_log_settings{.ifc_name = "eth_rpc_api"};
    InterfaceLogSettings engine_ifc_log_settings{.ifc_name = "engine_rpc_api"};
    concurrency::ContextPoolSettings context_pool_settings;
    std::optional<std::filesystem::path> datadir;
    std::string eth_end_point{kDefaultEth1EndPoint};
    std::string engine_end_point{kDefaultEngineEndPoint};
    std::string eth_api_spec{kDefaultEth1ApiSpec};
    std::string private_api_addr{kDefaultPrivateApiAddr};
    uint32_t num_workers{kDefaultNumWorkers};
    std::vector<std::string> cors_domain;
    std::optional<std::string> jwt_secret_file;
    bool skip_protocol_check{false};
    bool erigon_json_rpc_compatibility{false};
    bool use_websocket{false};
    bool ws_compression{false};
    bool http_compression{true};
};

}  // namespace silkworm::rpc
