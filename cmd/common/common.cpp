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

#include "common.hpp"

#include <CLI/CLI.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/infra/common/directories.hpp>

#include "ip_endpoint_option.hpp"

namespace silkworm::cmd::common {

//! CLI11 validator for an optional directory, checking that the folder exists if specified
struct OptionalExistingDirectory : public CLI::detail::ExistingDirectoryValidator {
    explicit OptionalExistingDirectory() {
        func_ = [](const std::optional<std::filesystem::path>& value) -> std::string {
            if (not value) return {};

            const auto path_result = CLI::detail::check_path(value->string().c_str());
            if (path_result == CLI::detail::path_type::nonexistent) {
                return "Directory does not exist: " + value->string();
            }
            if (path_result == CLI::detail::path_type::file) {
                return "Directory is actually a file: " + value->string();
            }
            return {};
        };
    }
};

void add_logging_options(CLI::App& cli, log::Settings& log_settings) {
    std::map<std::string, log::Level> level_mapping{
        {"critical", log::Level::kCritical},
        {"error", log::Level::kError},
        {"warning", log::Level::kWarning},
        {"info", log::Level::kInfo},
        {"debug", log::Level::kDebug},
        {"trace", log::Level::kTrace},
    };
    auto& log_opts = *cli.add_option_group("Log", "Logging options");
    log_opts.add_option("--log.verbosity", log_settings.log_verbosity, "Sets log verbosity")
        ->capture_default_str()
        ->check(CLI::Range(log::Level::kCritical, log::Level::kTrace))
        ->transform(CLI::Transformer(level_mapping, CLI::ignore_case))
        ->default_val(log_settings.log_verbosity);
    log_opts.add_flag("--log.stdout", log_settings.log_std_out, "Outputs to std::out instead of std::err");
    log_opts.add_flag("--log.colors", log_settings.log_colors, "Enable colors on log lines");
    log_opts.add_flag("--log.utc", log_settings.log_utc, "Prints log timings in UTC");
    log_opts.add_flag("--log.threads", log_settings.log_threads, "Prints thread ids");
    log_opts.add_option("--log.file", log_settings.log_file, "Tee all log lines to given file name");
}

void add_option_chain(CLI::App& cli, uint64_t& network_id) {
    cli.add_option("--chain", network_id, "Name or ID of the network to join (default: \"mainnet\")")
        ->transform(CLI::Transformer(get_known_chains_map(), CLI::ignore_case));
}

void add_option_data_dir(CLI::App& cli, std::filesystem::path& data_dir) {
    cli.add_option("--datadir", data_dir, "The path to the blockchain data directory")
        ->default_val(DataDirectory::get_default_storage_path().string());
}

void add_option_data_dir(CLI::App& cli, std::optional<std::filesystem::path>& data_dir) {
    cli.add_option("--datadir", data_dir, "The path to the blockchain data directory (optional)")
        ->check(OptionalExistingDirectory{})
        ->capture_default_str();
}

void add_option_etherbase(CLI::App& cli, std::string& etherbase_address) {
    cli.add_option("--etherbase", etherbase_address, "The coinbase address as hex string")
        ->default_val("");
}

void add_option_private_api_address(CLI::App& cli, std::string& private_api_address) {
    add_option_ip_endpoint(cli, "--private.api.addr", private_api_address,
                           "Private API network address to serve remote database interface\n"
                           "An empty string means to not start the listener\n"
                           "Use the endpoint form i.e. ip-address:port\n"
                           "DO NOT EXPOSE TO THE INTERNET");
}

void add_option_remote_sentry_addresses(CLI::App& cli, std::vector<std::string>& addresses, bool is_required) {
    cli.add_option("--sentry.remote.addr", addresses, "Remote Sentry gRPC API addresses (comma separated): <host>:<port>,<host2>:<port2>,...")
        ->delimiter(',')
        ->required(is_required)
        ->check(IPEndpointValidator(/*allow_empty=*/false));
}

//! \brief Set up parsing of the number of RPC execution contexts (i.e. threading model)
void add_option_num_contexts(CLI::App& cli, uint32_t& num_contexts) {
    cli.add_option("--contexts", num_contexts, "The number of execution contexts")
        ->default_val(std::thread::hardware_concurrency() / 2);
}

//! \brief Set up parsing of the wait mode (e.g. block, sleep, spin...) in RPC execution contexts
void add_option_wait_mode(CLI::App& cli, concurrency::WaitMode& wait_mode) {
    std::map<std::string, concurrency::WaitMode> wait_mode_mapping{
        {"backoff", concurrency::WaitMode::backoff},
        {"blocking", concurrency::WaitMode::blocking},
        {"busy_spin", concurrency::WaitMode::busy_spin},
        {"sleeping", concurrency::WaitMode::sleeping},
        {"yielding", concurrency::WaitMode::yielding},
    };
    cli.add_option("--wait.mode", wait_mode, "The waiting mode for execution loops during idle cycles")
        ->capture_default_str()
        ->check(CLI::Range(concurrency::WaitMode::backoff, concurrency::WaitMode::busy_spin))
        ->transform(CLI::Transformer(wait_mode_mapping, CLI::ignore_case))
        ->default_val(concurrency::WaitMode::blocking);
}

void add_context_pool_options(CLI::App& cli, concurrency::ContextPoolSettings& settings) {
    add_option_num_contexts(cli, settings.num_contexts);
    add_option_wait_mode(cli, settings.wait_mode);
}

std::string get_node_name_from_build_info(const buildinfo* build_info) {
    std::string node_name{"silkworm/"};
    node_name.append(build_info->git_branch);
    node_name.append(build_info->project_version);
    node_name.append("/");
    node_name.append(build_info->system_name);
    node_name.append("-");
    node_name.append(build_info->system_processor);
    node_name.append("_");
    node_name.append(build_info->build_type);
    node_name.append("/");
    node_name.append(build_info->compiler_id);
    node_name.append("-");
    node_name.append(build_info->compiler_version);
    return node_name;
}

}  // namespace silkworm::cmd::common
