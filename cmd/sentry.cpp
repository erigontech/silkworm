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

#include <filesystem>

#include <CLI/CLI.hpp>
#include <boost/process/environment.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/common/util.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/sentry/sentry.hpp>
#include <silkworm/sentry/settings.hpp>

#include "common.hpp"

using namespace silkworm;
using namespace silkworm::cmd;
using namespace silkworm::sentry;

Settings sentry_parse_cli_settings(int argc, char* argv[]) {
    CLI::App cli{"Sentry - P2P proxy"};

    Settings settings;
    settings.build_info = silkworm_get_buildinfo();
    add_logging_options(cli, settings.log_settings);

    cli.add_option("--sentry.api.addr", settings.api_address, "GRPC API endpoint")
        ->capture_default_str()
        ->check(IPEndPointValidator(/*allow_empty=*/true));

    cli.add_option("--port", settings.port)
        ->description("Network listening port for incoming peers TCP connections and discovery UDP requests")
        ->check(CLI::Range(1024, 65535))
        ->capture_default_str();

    auto nat_option = cli.add_option("--nat", [&settings](const CLI::results_t& results) {
        return lexical_cast(results[0], settings.nat);
    });
    nat_option->description(
        "NAT port mapping mechanism (none|extip:<IP>)\n"
        "- none              no NAT, use a local IP as public\n"
        "- extip:1.2.3.4     use the given public IP");
    nat_option->default_str("none");

    add_option_num_contexts(cli, settings.num_contexts);
    add_option_wait_mode(cli, settings.wait_mode);

    add_option_data_dir(cli, settings.data_dir_path);

    auto node_key_path_option = cli.add_option("--nodekey", [&settings](const CLI::results_t& results) {
        try {
            settings.node_key = {{std::filesystem::path(results[0])}};
            return true;
        } catch (const std::exception& e) {
            log::Error() << e.what();
            return false;
        }
    });
    node_key_path_option->description("P2P node key file");

    auto node_key_hex_option = cli.add_option("--nodekeyhex", [&settings](const CLI::results_t& results) {
        auto key_bytes = from_hex(results[0]);
        if (key_bytes) {
            settings.node_key = {{key_bytes.value()}};
        }
        return key_bytes.has_value();
    });
    node_key_hex_option->description("P2P node key as a hex string");

    auto static_peers_option = cli.add_option("--staticpeers", [&settings](const CLI::results_t& results) {
        try {
            for (auto& result : results) {
                if (result.empty()) continue;
                settings.static_peers.emplace_back(result);
            }
        } catch (const std::exception& e) {
            log::Error() << e.what();
            return false;
        }
        return true;
    });
    static_peers_option->description("Peers enode URLs to connect to without discovery");
    static_peers_option->type_size(1, INT_MAX);

    try {
        cli.parse(argc, argv);
    } catch (const CLI::ParseError& pe) {
        cli.exit(pe);
        throw;
    }

    return settings;
}

void sentry_main(Settings settings) {
    log::init(settings.log_settings);
    log::set_thread_name("main");
    // TODO(canepat): this could be an option in Silkworm logging facility
    silkworm::rpc::Grpc2SilkwormLogGuard log_guard;

    Sentry sentry{std::move(settings)};
    sentry.start();

    const auto pid = boost::this_process::get_id();
    const auto tid = std::this_thread::get_id();
    log::Info() << "Sentry is now running [pid=" << pid << ", main thread=" << tid << "]";
    sentry.join();

    log::Info() << "Sentry exiting [pid=" << pid << ", main thread=" << tid << "]";
}

int main(int argc, char* argv[]) {
    try {
        sentry_main(sentry_parse_cli_settings(argc, argv));
    } catch (const CLI::ParseError& pe) {
        return -1;
    } catch (const std::exception& e) {
        log::Critical() << "Sentry exiting due to exception: " << e.what();
        return -2;
    } catch (...) {
        log::Critical() << "Sentry exiting due to unexpected exception";
        return -3;
    }
}
