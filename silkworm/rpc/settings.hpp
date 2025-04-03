// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
    bool standalone{true};
    bool skip_protocol_check{false};
    bool erigon_json_rpc_compatibility{false};
    bool use_websocket{false};
    bool ws_compression{false};
    bool http_compression{true};
};

}  // namespace silkworm::rpc
