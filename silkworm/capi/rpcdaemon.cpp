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

#include <silkworm/db/data_store.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/daemon.hpp>
#include <silkworm/rpc/settings.hpp>

#include "common.hpp"
#include "instance.hpp"
#include "silkworm.h"

using namespace silkworm;
using namespace silkworm::rpc;

//! Build interface log settings for ETH JSON-RPC from their C representation
static InterfaceLogSettings make_eth_ifc_log_settings(const struct SilkwormRpcInterfaceLogSettings settings) {
    InterfaceLogSettings eth_ifc_log_settings{.ifc_name = "eth_rpc_api"};
    eth_ifc_log_settings.enabled = settings.enabled;
    eth_ifc_log_settings.container_folder = parse_path(settings.container_folder);
    eth_ifc_log_settings.max_file_size_mb = settings.max_file_size_mb;
    eth_ifc_log_settings.max_files = settings.max_files;
    eth_ifc_log_settings.dump_response = settings.dump_response;
    return eth_ifc_log_settings;
}

//! Build JSON-RPC endpoint from C settings
static std::string parse_end_point(const char (&c_host)[SILKWORM_RPC_SETTINGS_HOST_SIZE], int port, const std::string& default_end_point) {
    auto host = std::string{c_host};
    if (host.empty() && port == 0) {
        return kDefaultEth1EndPoint;
    }
    const auto semicolon_position{default_end_point.find(':')};
    SILKWORM_ASSERT(semicolon_position != std::string::npos);
    if (host.empty()) {
        host = default_end_point.substr(0, semicolon_position);
    }
    if (port == 0) {
        port = std::stoi(default_end_point.substr(semicolon_position + 1));
    }
    std::string eth_end_point{host + ":" + std::to_string(port)};
    return eth_end_point;
}

//! Build list of CORS domains from their C representation
static std::vector<std::string> parse_cors_domains(
    const char (&c_cors_domains)[SILKWORM_RPC_SETTINGS_CORS_DOMAINS_MAX][SILKWORM_RPC_SETTINGS_CORS_DOMAIN_SIZE]) {
    std::vector<std::string> cors_domains;
    for (const auto& c_domain : c_cors_domains) {
        std::string_view domain_str = c_domain;
        if (domain_str.empty()) break;
        cors_domains.emplace_back(domain_str);
    }
    return cors_domains;
}

//! Build whole RPC daemon settings from their C representation
static DaemonSettings make_daemon_settings(SilkwormHandle handle, const struct SilkwormRpcSettings& settings) {
    const auto jwt_path{parse_path(settings.jwt_file_path)};
    return {
        .log_settings = handle->log_settings,
        .eth_ifc_log_settings = make_eth_ifc_log_settings(settings.eth_if_log_settings),
        .context_pool_settings = handle->context_pool_settings,
        .eth_end_point = parse_end_point(settings.eth_api_host, settings.eth_api_port, kDefaultEth1EndPoint),
        .engine_end_point = "",  // disable end-point for Engine RPC API
        .eth_api_spec = std::string{settings.eth_api_spec},
        .num_workers = settings.num_workers > 0 ? settings.num_workers : kDefaultNumWorkers,
        .cors_domain = parse_cors_domains(settings.cors_domains),
        .jwt_secret_file = jwt_path.empty() ? std::nullopt : std::make_optional(jwt_path.string()),
        .skip_protocol_check = settings.skip_internal_protocol_check,
        .erigon_json_rpc_compatibility = settings.erigon_json_rpc_compatibility,
        .use_websocket = settings.ws_enabled,
        .ws_compression = settings.ws_compression,
        .http_compression = settings.http_compression,
    };
}

SILKWORM_EXPORT int silkworm_start_rpcdaemon(SilkwormHandle handle, MDBX_env* env, const struct SilkwormRpcSettings* settings) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (handle->rpcdaemon) {
        return SILKWORM_SERVICE_ALREADY_STARTED;
    }
    if (!env) {
        return SILKWORM_INVALID_MDBX_ENV;
    }
    if (!settings) {
        return SILKWORM_INVALID_SETTINGS;
    }

    auto daemon_settings = make_daemon_settings(handle, *settings);
    handle->chaindata = std::make_unique<datastore::kvdb::DatabaseUnmanaged>(
        db::DataStore::make_chaindata_database(datastore::kvdb::EnvUnmanaged{env}));

    db::DataStoreRef data_store{
        handle->chaindata->ref(),
        *handle->blocks_repository,
        *handle->state_repository_latest,
        *handle->state_repository_historical,
    };

    // Create the one-and-only Silkrpc daemon
    handle->rpcdaemon = std::make_unique<rpc::Daemon>(daemon_settings, data_store);

    // Check protocol version compatibility with Core Services
    if (!daemon_settings.skip_protocol_check) {
        SILK_INFO << "[Silkworm RPC] Checking protocol version compatibility with core services...";

        const auto checklist = handle->rpcdaemon->run_checklist();
        for (const auto& protocol_check : checklist.protocol_checklist) {
            SILK_INFO << protocol_check.result;
        }
        checklist.success_or_throw();
    } else {
        SILK_TRACE << "[Silkworm RPC] Skip protocol version compatibility check with core services";
    }

    SILK_INFO << "[Silkworm RPC] Starting ETH API at " << daemon_settings.eth_end_point;
    try {
        handle->rpcdaemon->start();
    } catch (const std::exception& ex) {
        SILK_ERROR << "[Silkworm RPC] Cannot start RPC daemon due to: " << ex.what();
        return SILKWORM_INTERNAL_ERROR;
    }

    return SILKWORM_OK;
}

SILKWORM_EXPORT int silkworm_stop_rpcdaemon(SilkwormHandle handle) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!handle->rpcdaemon) {
        return SILKWORM_OK;
    }

    try {
        handle->rpcdaemon->stop();
        SILK_INFO << "[Silkworm RPC] Exiting...";
        handle->rpcdaemon->join();
        SILK_INFO << "[Silkworm RPC] Stopped";
        handle->rpcdaemon.reset();
    } catch (const std::exception& ex) {
        SILK_ERROR << "[Silkworm RPC] Cannot stop RPC daemon due to: " << ex.what();
        return SILKWORM_INTERNAL_ERROR;
    }

    return SILKWORM_OK;
}
