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

#include <string>
#include <thread>

#include <CLI/CLI.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/process/environment.hpp>

#include <silkworm/backend/ethereum_backend.hpp>
#include <silkworm/buildinfo.h>
#include <silkworm/chain/config.hpp>
#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/rpc/server/backend_kv_server.hpp>
#include <silkworm/rpc/util.hpp>

#include "common.hpp"

//! Assemble the full node name using the Cable build information
std::string get_node_name_from_build_info() {
    const auto build_info{silkworm_get_buildinfo()};

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

//! Assemble the relevant library version information
std::string get_library_versions() {
    std::string library_versions{"gRPC: "};
    library_versions.append(grpc::Version());
    library_versions.append(" MDBX: ");
    library_versions.append(mdbx::get_version().git.describe);
    return library_versions;
}

//! The overall settings for the BackEnd and KV standalone server
struct BackEndKvSettings {
    silkworm::log::Settings log_settings;
    silkworm::NodeSettings node_settings;
    silkworm::rpc::ServerConfig server_settings;
};

//! Parse the command-line arguments into the BackEnd and KV server settings
int parse_command_line(int argc, char* argv[], CLI::App& app, BackEndKvSettings& settings) {
    auto& log_settings = settings.log_settings;
    auto& node_settings = settings.node_settings;
    auto& server_settings = settings.server_settings;

    std::string data_dir{silkworm::DataDirectory::get_default_storage_path().string()};
    std::string etherbase_address{""};
    uint32_t num_contexts{std::thread::hardware_concurrency() / 2};
    silkworm::rpc::WaitMode wait_mode{silkworm::rpc::WaitMode::blocking};
    uint32_t max_readers{silkworm::db::EnvConfig{}.max_readers};
    app.add_option("--datadir", data_dir, "The path to data directory")->capture_default_str();
    app.add_option("--etherbase", etherbase_address, "The coinbase address as string")->capture_default_str();
    // TODO(canepat) add check on etherbase using EthAddressValidator [TBD]
    silkworm::cmd::add_option_num_contexts(app, num_contexts);
    silkworm::cmd::add_option_wait_mode(app, wait_mode);
    app.add_option("--mdbx.max.readers", max_readers, "The maximum number of MDBX readers")
        ->capture_default_str()
        ->check(CLI::Range(1, 32767));

    // RPC Server options
    app.add_option("--private.api.addr", node_settings.private_api_addr,
                   "Private API network address to serve remote database interface\n"
                   "An empty string means to not start the listener\n"
                   "Use the endpoint form i.e. ip-address:port\n"
                   "DO NOT EXPOSE TO THE INTERNET")
        ->capture_default_str();
    // TODO(canepat) add check on private.api.addr using IPEndPointValidator
    app.add_option("--sentry.api.addr", node_settings.sentry_api_addr, "Sentry api endpoint")->capture_default_str();
    // TODO(canepat) add check on sentry_api_addr using IPEndPointValidator

    // Chain options
    auto& chain_opts = *app.add_option_group("Chain", "Chain selection options");
    auto chain_name = chain_opts.add_option("--chain", "Name of the network to join (default: \"mainnet\")")
                          ->transform(CLI::Transformer(silkworm::get_known_chains_map(), CLI::ignore_case));
    chain_opts
        .add_option("--networkid", node_settings.network_id,
                    "Explicitly set network id\n"
                    "For known networks: use --chain <testnet_name> instead")
        ->capture_default_str()
        ->excludes(chain_name);

    silkworm::cmd::add_logging_options(app, log_settings);

    app.parse(argc, argv);

    if (chain_name->count()) {
        node_settings.network_id = chain_name->as<uint32_t>();
    }

    auto known_chain_config{silkworm::lookup_known_chain(node_settings.network_id)};
    if (!known_chain_config.has_value()) {
        SILK_CRIT << "Unknown chain identifier: " << node_settings.network_id;
        return -1;
    }
    node_settings.chain_config = *(known_chain_config->second);

    if (!etherbase_address.empty()) {
        const auto etherbase = silkworm::from_hex(etherbase_address);
        if (!etherbase) {
            SILK_CRIT << "Invalid etherbase address: " << etherbase_address;
            return -1;
        }
        node_settings.etherbase = silkworm::to_evmc_address(etherbase.value());
    }

    node_settings.data_directory = std::make_unique<silkworm::DataDirectory>(data_dir, /*create=*/false);
    node_settings.chaindata_env_config =
        silkworm::db::EnvConfig{node_settings.data_directory->chaindata().path().string(),
                                /*create=*/false,
                                /*readonly=*/true};
    node_settings.chaindata_env_config.max_readers = max_readers;

    server_settings.set_address_uri(node_settings.private_api_addr);
    server_settings.set_num_contexts(num_contexts);
    server_settings.set_wait_mode(wait_mode);

    return 0;
}

int main(int argc, char* argv[]) {
    CLI::App app{"ETHBACKEND & KV server"};

    try {
        BackEndKvSettings settings;
        int result_code = parse_command_line(argc, argv, app, settings);
        if (result_code != 0) {
            return result_code;
        }

        const auto node_name{get_node_name_from_build_info()};
        SILK_LOG << "BackEndKvServer build info: " << node_name << " " << get_library_versions();

        const auto pid = boost::this_process::get_id();
        const auto tid = std::this_thread::get_id();

        auto& log_settings = settings.log_settings;
        auto& node_settings = settings.node_settings;
        auto& server_settings = settings.server_settings;

        // Initialize logging with custom settings
        silkworm::log::init(log_settings);

        // TODO(canepat): this could be an option in Silkworm logging facility
        silkworm::rpc::Grpc2SilkwormLogGuard log_guard;

        SILK_LOG << "BackEndKvServer launched with address: " << server_settings.address_uri()
                 << ", contexts: " << server_settings.num_contexts();

        auto database_env = silkworm::db::open_env(node_settings.chaindata_env_config);
        silkworm::EthereumBackEnd backend{node_settings, &database_env};
        backend.set_node_name(node_name);

        SILK_INFO << "BackEndKvServer MDBX max readers: " << database_env.max_readers();

        silkworm::rpc::BackEndKvServer server{server_settings, backend};
        server.build_and_start();

        boost::asio::io_context& scheduler = server.next_io_context();
        boost::asio::signal_set signals{scheduler, SIGINT, SIGTERM};

        SILK_DEBUG << "Signals registered on scheduler " << &scheduler;
        signals.async_wait([&](const boost::system::error_code& error, int signal_number) {
            std::cout << "\n";
            SILK_INFO << "Signal caught, error: " << error << " number: " << signal_number;
            backend.close();
            server.shutdown();
        });

        SILK_LOG << "BackEndKvServer is now running [pid=" << pid << ", main thread=" << tid << "]";
        server.join();

        SILK_LOG << "BackEndKvServer exiting [pid=" << pid << ", main thread=" << tid << "]";
        return 0;
    } catch (const CLI::ParseError& pe) {
        return app.exit(pe);
    } catch (const std::exception& e) {
        SILK_CRIT << "BackEndKvServer exiting due to exception: " << e.what();
        return -2;
    } catch (...) {
        SILK_CRIT << "BackEndKvServer exiting due to unexpected exception";
        return -3;
    }
}
