/*
   Copyright 2024 The Silkworm Authors

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

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/idle_strategy.hpp>
#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/common/interface_log.hpp>

namespace silkworm::chainsync {

struct EngineRpcSettings {
    std::string engine_end_point{kDefaultEngineEndPoint};
    rpc::InterfaceLogSettings engine_ifc_log_settings{.ifc_name = "engine_rpc_api"};
    std::string private_api_addr{kDefaultPrivateApiAddr};
    log::Level log_verbosity{log::Level::kInfo};
    concurrency::WaitMode wait_mode{concurrency::WaitMode::kBlocking};
    std::optional<std::string> jwt_secret_file;
};

struct Settings {
    std::string client_id{"silkworm"};
    std::string private_api_addr{kDefaultPrivateApiAddr};
    log::Settings log_settings;
    EngineRpcSettings rpc_settings;
};

}  // namespace silkworm::chainsync
