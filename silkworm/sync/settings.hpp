// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <string>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/common/interface_log.hpp>

namespace silkworm::chainsync {

struct EngineRpcSettings {
    std::string engine_end_point{kDefaultEngineEndPoint};
    rpc::InterfaceLogSettings engine_ifc_log_settings{.ifc_name = "engine_rpc_api"};
    std::string private_api_addr{kDefaultPrivateApiAddr};
    log::Level log_verbosity{log::Level::kInfo};
    std::optional<std::string> jwt_secret_file;
};

struct Settings {
    std::string client_id{"silkworm"};
    std::string private_api_addr{kDefaultPrivateApiAddr};
    log::Settings log_settings;
    EngineRpcSettings rpc_settings;
};

}  // namespace silkworm::chainsync
