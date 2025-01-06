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
            if (!value) return {};

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
        ->check(CLI::Range(log::Level::kCritical, log::Level::kTrace))
        ->transform(CLI::Transformer(level_mapping, CLI::ignore_case))
        ->default_val(log::Level::kInfo);
    log_opts.add_flag("--log.stdout", log_settings.log_std_out, "Outputs to std::out instead of std::err");
    log_opts.add_flag("--log.nocolor", log_settings.log_nocolor, "Disable colors on log lines");
    log_opts.add_flag("--log.utc", log_settings.log_utc, "Prints log timings in UTC");
    log_opts.add_flag("--log.threads", log_settings.log_threads, "Prints thread ids");
    log_opts.add_option("--log.file", log_settings.log_file, "Tee all log lines to given file name");
}

void add_option_chain(CLI::App& cli, uint64_t& network_id) {
    cli.add_option("--chain", network_id, "Name or ID of the network to join (default: \"mainnet\")")
        ->transform(CLI::Transformer(kKnownChainNameToId.to_std_map<std::string>(), CLI::ignore_case));
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

void add_context_pool_options(CLI::App& cli, concurrency::ContextPoolSettings& settings) {
    add_option_num_contexts(cli, settings.num_contexts);
}

}  // namespace silkworm::cmd::common
