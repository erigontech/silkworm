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

#include <string>

#include <absl/flags/flag.h>
#include <absl/flags/parse.h>
#include <absl/flags/usage.h>
#include <absl/flags/usage_config.h>
#include <absl/strings/match.h>
#include <boost/asio/version.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/buildinfo.h>
#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/config.hpp>
#include <silkworm/silkrpc/daemon.hpp>

#include "../common/common.hpp"

using namespace silkworm::cmd;

ABSL_FLAG(std::string, chaindata, silkrpc::kEmptyChainData, "chain data path as string");
ABSL_FLAG(std::string, http_port, silkrpc::kDefaultHttpPort, "Ethereum JSON RPC API local end-point as string <address>:<port>");
ABSL_FLAG(std::string, engine_port, silkrpc::kDefaultEnginePort, "Engine JSON RPC API local end-point as string <address>:<port>");
ABSL_FLAG(std::string, target, silkrpc::kDefaultTarget, "Erigon Core gRPC service location as string <address>:<port>");
ABSL_FLAG(std::string, api_spec, silkrpc::kDefaultEth1ApiSpec, "JSON RPC API namespaces as comma-separated list of strings");
ABSL_FLAG(uint32_t, num_contexts, std::thread::hardware_concurrency() / 3, "number of running I/O contexts as 32-bit integer");
ABSL_FLAG(uint32_t, num_workers, 16, "number of worker threads as 32-bit integer");
ABSL_FLAG(uint32_t, timeout, silkrpc::kDefaultTimeout.count(), "gRPC call timeout as 32-bit integer");
ABSL_FLAG(silkrpc::LogLevel, log_verbosity, silkrpc::LogLevel::Critical, "logging verbosity level");
ABSL_FLAG(silkrpc::WaitMode, wait_mode, silkrpc::WaitMode::blocking, "scheduler wait mode");
ABSL_FLAG(std::string, jwt_secret_file, silkrpc::kDefaultJwtFilename, "Token file to ensure safe connection between CL and EL");
ABSL_FLAG(std::string, datadir, silkrpc::kDefaultDataDir, "DB Path");

//! Assemble the application version using the Cable build information
std::string get_version_from_build_info() {
    const auto build_info{silkworm_get_buildinfo()};

    std::string application_version{"silkrpcdaemon version: "};
    application_version.append(build_info->project_version);
    return application_version;
}

//! Assemble the application fully-qualified name using the Cable build information
std::string get_name_from_build_info() {
    return common::get_node_name_from_build_info(silkworm_get_buildinfo());
}

//! Assemble the relevant library version information
std::string get_library_versions() {
    std::string library_versions{"gRPC: "};
    library_versions.append(grpc::Version());
    library_versions.append(" Boost Asio: ");
    library_versions.append(std::to_string(BOOST_ASIO_VERSION));
    return library_versions;
}

silkrpc::DaemonSettings parse_args(int argc, char* argv[]) {
    absl::FlagsUsageConfig config;
    config.contains_helpshort_flags = [](absl::string_view) { return false; };
    config.contains_help_flags = [](absl::string_view filename) { return absl::EndsWith(filename, "main.cpp"); };
    config.contains_helppackage_flags = [](absl::string_view) { return false; };
    config.normalize_filename = [](absl::string_view f) { return std::string{f.substr(f.rfind('/') + 1)}; };
    config.version_string = []() { return get_version_from_build_info() + "\n"; };
    absl::SetFlagsUsageConfig(config);
    absl::SetProgramUsageMessage("C++ implementation of Ethereum JSON RPC API service within Thorax architecture");
    absl::ParseCommandLine(argc, argv);

    const auto datadir = absl::GetFlag(FLAGS_datadir);
    std::optional<std::string> datadir_optional;
    if (!datadir.empty()) {
        datadir_optional = datadir;
    }
    silkrpc::DaemonSettings rpc_daemon_settings{
        datadir_optional,
        absl::GetFlag(FLAGS_http_port),
        absl::GetFlag(FLAGS_engine_port),
        absl::GetFlag(FLAGS_api_spec),
        absl::GetFlag(FLAGS_target),
        absl::GetFlag(FLAGS_num_contexts),
        absl::GetFlag(FLAGS_num_workers),
        absl::GetFlag(FLAGS_log_verbosity),
        absl::GetFlag(FLAGS_wait_mode),
        absl::GetFlag(FLAGS_jwt_secret_file),
    };
    return rpc_daemon_settings;
}

int main(int argc, char* argv[]) {
    return silkrpc::Daemon::run(parse_args(argc, argv), {get_name_from_build_info(), get_library_versions()});
}
