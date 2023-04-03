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

#include <regex>
#include <stdexcept>

#include <boost/asio/ip/address.hpp>

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/node/db/access_layer.hpp>

namespace silkworm::cmd::common {

PruneModeValidator::PruneModeValidator() {
    func_ = [](const std::string& value) -> std::string {
        if (value.find_first_not_of("hrtc") != std::string::npos) {
            return "Value " + value + " contains other characters other than h r t c";
        }
        return {};
    };
}

IPEndPointValidator::IPEndPointValidator(bool allow_empty) {
    func_ = [&allow_empty](const std::string& value) -> std::string {
        if (value.empty() && allow_empty) {
            return {};
        }

        const std::regex pattern(R"(([\da-fA-F\.\:]*)\:([\d]*))");
        std::smatch matches;
        if (!std::regex_match(value, matches, pattern)) {
            return "Value " + value + " is not a valid endpoint";
        }

        // Validate IP address
        boost::system::error_code err;
        boost::asio::ip::make_address(matches[1], err).to_string();
        if (err) {
            return "Value " + std::string(matches[1]) + " is not a valid ip address";
        }

        // Validate port
        int port{std::stoi(matches[2])};
        if (port < 1 || port > 65535) {
            return "Value " + std::string(matches[2]) + " is not a valid listening port";
        }

        return {};
    };
}

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
    log_opts.add_flag("--log.nocolor", log_settings.log_nocolor, "Disable colors on log lines");
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

void add_option_etherbase(CLI::App& cli, std::string& etherbase_address) {
    cli.add_option("--etherbase", etherbase_address, "The coinbase address as hex string")
        ->default_val("");
}

void add_option_db_max_readers(CLI::App& cli, uint32_t& max_readers) {
    cli.add_option("--mdbx.max.readers", max_readers, "The maximum number of MDBX readers")
        ->default_val(silkworm::db::EnvConfig{}.max_readers)
        ->check(CLI::Range(1, 32767));
}

void add_option_private_api_address(CLI::App& cli, std::string& private_api_address) {
    add_option_ip_address(cli, "--private.api.addr", private_api_address,
                          "Private API network address to serve remote database interface\n"
                          "An empty string means to not start the listener\n"
                          "Use the endpoint form i.e. ip-address:port\n"
                          "DO NOT EXPOSE TO THE INTERNET");
}

void add_option_sentry_api_address(CLI::App& cli, std::string& sentry_api_address) {
    add_option_ip_address(cli, "--sentry.api.addr", sentry_api_address, "Sentry api endpoint");
}

void add_option_external_sentry_address(CLI::App& cli, std::string& external_sentry_address) {
    add_option_ip_address(cli, "--sentry.remote.addr", external_sentry_address, "External Sentry endpoint");
}

void add_option_ip_address(CLI::App& cli, const std::string& name, std::string& address, const std::string& description) {
    cli.add_option(name, address, description)
        ->capture_default_str()
        ->check(IPEndPointValidator(/*allow_empty=*/true));
}

void add_option_num_contexts(CLI::App& cli, uint32_t& num_contexts) {
    cli.add_option("--contexts", num_contexts, "The number of execution contexts")
        ->default_val(std::thread::hardware_concurrency() / 2);
}

void add_option_wait_mode(CLI::App& cli, silkworm::rpc::WaitMode& wait_mode) {
    std::map<std::string, silkworm::rpc::WaitMode> wait_mode_mapping{
        {"backoff", silkworm::rpc::WaitMode::backoff},
        {"blocking", silkworm::rpc::WaitMode::blocking},
        {"busy_spin", silkworm::rpc::WaitMode::busy_spin},
        {"sleeping", silkworm::rpc::WaitMode::sleeping},
        {"yielding", silkworm::rpc::WaitMode::yielding},
    };
    cli.add_option("--wait.mode", wait_mode, "The waiting mode for execution loops during idle cycles")
        ->capture_default_str()
        ->check(CLI::Range(silkworm::rpc::WaitMode::backoff, silkworm::rpc::WaitMode::busy_spin))
        ->transform(CLI::Transformer(wait_mode_mapping, CLI::ignore_case))
        ->default_val(silkworm::rpc::WaitMode::blocking);
}

void add_snapshot_options(CLI::App& cli, SnapshotSettings& snapshot_settings) {
    cli.add_flag("--snapshots.enabled", snapshot_settings.enabled,
                 "Flag indicating if usage of snapshots should be enabled or disable");
    cli.add_flag("--snapshots.no_downloader", snapshot_settings.no_downloader,
                 "If set, the snapshot downloader is disabled and just already present local snapshots are used");

    // TODO(canepat) add options for the other snapshot settings and for all bittorrent settings
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
