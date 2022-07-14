/*
Copyright 2021-2022 The Silkworm Authors

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
#include <boost/asio/signal_set.hpp>
#include <boost/process/environment.hpp>

#include <silkworm/common/util.hpp>
#include <silkworm/rpc/util.hpp>
#include <sentry/options.hpp>
#include <sentry/node_key_config.hpp>
#include <sentry/server.hpp>
#include "common.hpp"

using namespace silkworm;
using namespace silkworm::cmd;
using namespace silkworm::sentry;

int sentry_main(int argc, char* argv[]) {
    CLI::App cli{"Sentry - P2P proxy"};

    log::Settings log_settings;
    add_logging_options(cli, log_settings);

    Options options;
    cli.add_option("--sentry.api.addr", options.api_address, "GRPC API endpoint")
        ->capture_default_str()
        ->check(IPEndPointValidator(/*allow_empty=*/true));

    cli.add_option("--port", options.port)
        ->description("Network listening port for incoming peers TCP connections and discovery UDP requests")
        ->check(CLI::Range(1024, 65535))
        ->capture_default_str();

    auto nat_option = cli.add_option("--nat", [&options](CLI::results_t results) {
       return lexical_cast(results[0], options.nat);
    });
    nat_option->description("NAT port mapping mechanism (none|extip:<IP>)\n"
            "- none              no NAT, use a local IP as public\n"
            "- extip:1.2.3.4     use the given public IP");
    nat_option->default_str("none");

    add_option_num_contexts(cli, options.num_contexts);
    add_option_wait_mode(cli, options.wait_mode);

    add_option_data_dir(cli, options.data_dir_path);

    auto node_key_path_option = cli.add_option("--nodekey", [&options](CLI::results_t results) {
        try {
            options.node_key = {{std::filesystem::path(results[0])}};
            return true;
        } catch (const std::exception& e) {
            log::Error() << e.what();
            return false;
        }
    });
    node_key_path_option->description("P2P node key file");

    auto node_key_hex_option = cli.add_option("--nodekeyhex", [&options](CLI::results_t results) {
        auto key_bytes = from_hex(results[0]);
        if (key_bytes) {
            options.node_key = {{key_bytes.value()}};
        }
        return key_bytes.has_value();
    });
    node_key_hex_option->description("P2P node key as a hex string");

    auto static_peers_option = cli.add_option("--staticpeers", [&options](CLI::results_t results) {
        try {
            for (auto& result : results) {
                if (result.empty()) continue;
                options.static_peers.emplace_back(result);
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
        return cli.exit(pe);
    }

    log::init(log_settings);
    log::set_thread_name("main");
    // TODO(canepat): this could be an option in Silkworm logging facility
    silkworm::rpc::Grpc2SilkwormLogGuard log_guard;

    // TODO: move inside the Server
    DataDirectory data_dir{options.data_dir_path, true};
    [[maybe_unused]]
    NodeKey node_key = node_key_get_or_generate(options.node_key, data_dir);

    Server server{options};
    server.build_and_start();

    boost::asio::signal_set signals{server.next_io_context(), SIGINT, SIGTERM};
    signals.async_wait([&](const boost::system::error_code& error, int signal_number) {
        log::Info() << "\n";
        log::Info() << "Signal caught, error: " << error << " number: " << signal_number;
        server.shutdown();
    });

    const auto pid = boost::this_process::get_id();
    const auto tid = std::this_thread::get_id();
    log::Info() << "Sentry is now running [pid=" << pid << ", main thread=" << tid << "]";
    server.join();

    log::Info() << "Sentry exiting [pid=" << pid << ", main thread=" << tid << "]";
    return 0;
}

int main(int argc, char* argv[]) {
    try {
        return sentry_main(argc, argv);
    } catch (const std::exception& e) {
        log::Critical() << "Sentry exiting due to exception: " << e.what();
        return -2;
    } catch (...) {
        log::Critical() << "Sentry exiting due to unexpected exception";
        return -3;
    }
}
