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

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/context_pool_settings.hpp>
#include <silkworm/rpc/common/constants.hpp>

namespace silkworm::rpc {

struct DaemonSettings {
    log::Settings log_settings;
    concurrency::ContextPoolSettings context_pool_settings;
    std::optional<std::filesystem::path> datadir;
    std::string eth_end_point{kDefaultEth1EndPoint};
    std::string engine_end_point{kDefaultEngineEndPoint};
    std::string eth_api_spec{kDefaultEth1ApiSpec};
    std::string private_api_addr{kDefaultPrivateApiAddr};
    uint32_t num_workers{std::thread::hardware_concurrency() / 2};
    std::vector<std::string> cors_domain;
    std::optional<std::string> jwt_secret_file;
    bool skip_protocol_check{false};
    bool erigon_json_rpc_compatibility{false};
};

}  // namespace silkworm::rpc
