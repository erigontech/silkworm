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

#include <iostream>
#include <string>
#include <thread>

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/process/environment.hpp>
#include <CLI/CLI.hpp>
#include <magic_enum.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/chain/config.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/rpc/backend_kv_server.hpp>

std::string get_node_name_from_build_info() {
    const auto build_info{silkworm_get_buildinfo()};

    std::string node_name{"silkworm/"};
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

int main(int argc, char* argv[]) {
    const auto pid = boost::this_process::get_id();
    const auto tid = std::this_thread::get_id();

    CLI::App app{"ETHBACKEND & KV servers"};

    std::string chain_id{"mainnet"};
    std::string address_uri{"localhost:9090"};
    uint32_t num_contexts{std::thread::hardware_concurrency() / 2};
    silkworm::log::Level log_level{silkworm::log::Level::kCritical};
    app.add_option("--chain", chain_id, "The chain identifier as string", true);
    app.add_option("--address", address_uri, "The address URI to bind the ETHBACKEND & KV services to", true);
    app.add_option("--numContexts", num_contexts, "The number of running contexts", true);
    app.add_option("--logLevel", log_level, "The log level identifier as string", true)
        ->check(CLI::Range(static_cast<uint32_t>(silkworm::log::Level::kCritical), static_cast<uint32_t>(silkworm::log::Level::kTrace)))
        ->default_val(std::to_string(static_cast<uint32_t>(log_level)));

    CLI11_PARSE(app, argc, argv);

    const silkworm::ChainConfig* chain_config = silkworm::lookup_chain_config(chain_id);
    if (chain_config == nullptr) {
        SILK_CRIT << "Invalid chain identifier: " << chain_id;
        return -1;
    }

    silkworm::log::Settings log_settings{};
    log_settings.log_nocolor = true;
    log_settings.log_threads = true;
    log_settings.log_verbosity = log_level;
    silkworm::log::init(log_settings);

    const auto node_name{get_node_name_from_build_info()};
    SILK_LOG << "BackEndKvServer build info: " << node_name << " gRPC version: " << grpc::Version();

    try {
        SILK_LOG << "BackEndKvServer launched with address: " << address_uri << ", contexts: " << num_contexts;

        silkworm::rpc::ServerConfig srv_config;
        srv_config.set_node_name(node_name);
        srv_config.set_address_uri(address_uri);
        srv_config.set_num_contexts(num_contexts);

        silkworm::rpc::BackEndKvServer server{srv_config, *chain_config};
        server.build_and_start();

        boost::asio::io_context& scheduler = server.next_io_context();
        boost::asio::signal_set signals{scheduler, SIGINT, SIGTERM};

        SILK_DEBUG << "Signals registered on scheduler " << &scheduler;
        signals.async_wait([&](const boost::system::error_code& error, int signal_number) {
            std::cout << "\n";
            SILK_INFO << "Signal caught, error: " << error << " number: " << signal_number;
            std::thread shutdown_thread{[&server]() {
                server.shutdown();
            }};
            shutdown_thread.detach();
        });

        SILK_LOG << "BackEndKvServer is now running [pid=" << pid << ", main thread=" << tid << "]";
        server.join();

        SILK_LOG << "BackEndKvServer exiting [pid=" << pid << ", main thread=" << tid << "]";
        return 0;
    } catch (const std::exception& e) {
        SILK_CRIT << "BackEndKvServer exiting due to exception: " << e.what();
        return -2;
    } catch (...) {
        SILK_CRIT << "BackEndKvServer exiting due to unexpected exception";
        return -3;
    }
}
