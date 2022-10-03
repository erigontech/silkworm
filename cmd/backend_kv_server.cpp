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
#include <string>

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

using namespace silkworm;

//! Assemble the relevant library version information
std::string get_library_versions() {
    std::string library_versions{"gRPC: "};
    library_versions.append(grpc::Version());
    library_versions.append(" MDBX: ");
    library_versions.append(mdbx::get_version().git.describe);
    return library_versions;
}

//! Parse the command-line arguments into the BackEnd and KV server settings
int parse_command_line(int argc, char* argv[], CLI::App& app, cmd::SilkwormCoreSettings& settings) {
    auto& log_settings = settings.log_settings;
    auto& node_settings = settings.node_settings;
    auto& server_settings = settings.server_settings;

    // Node options
    cmd::add_option_chain(app, node_settings.network_id);

    std::filesystem::path data_dir;
    cmd::add_option_data_dir(app, data_dir);

    std::string etherbase_address;
    cmd::add_option_etherbase(app, etherbase_address);

    uint32_t max_readers;
    cmd::add_option_db_max_readers(app, max_readers);

    // RPC Server options
    cmd::add_option_private_api_address(app, node_settings.private_api_addr);
    cmd::add_option_sentry_api_address(app, node_settings.sentry_api_addr);

    uint32_t num_contexts;
    cmd::add_option_num_contexts(app, num_contexts);

    rpc::WaitMode wait_mode;
    cmd::add_option_wait_mode(app, wait_mode);

    // Logging options
    cmd::add_logging_options(app, log_settings);

    app.parse(argc, argv);

    // Validate and assign settings
    // TODO (canepat) read chain config from database (allows for custom config)
    const auto known_chain_config{lookup_known_chain(node_settings.network_id)};
    if (!known_chain_config.has_value()) {
        SILK_CRIT << "Unknown chain identifier: " << node_settings.network_id;
        return -1;
    }
    node_settings.chain_config = *(known_chain_config->second);

    if (!etherbase_address.empty()) {
        const auto etherbase = from_hex(etherbase_address);
        if (!etherbase) {
            SILK_CRIT << "Invalid etherbase address: " << etherbase_address;
            return -1;
        }
        node_settings.etherbase = to_evmc_address(etherbase.value());
    }

    node_settings.data_directory = std::make_unique<DataDirectory>(data_dir, /*create=*/false);
    node_settings.chaindata_env_config = db::EnvConfig{node_settings.data_directory->chaindata().path().string(),
                                                       /*create=*/false,
                                                       /*readonly=*/true};
    node_settings.chaindata_env_config.max_readers = max_readers;

    server_settings.set_address_uri(node_settings.private_api_addr);
    server_settings.set_num_contexts(num_contexts);
    server_settings.set_wait_mode(wait_mode);

    return 0;
}

int main(int argc, char* argv[]) {
    CLI::App cli{"ETHBACKEND & KV server"};

    try {
        cmd::SilkwormCoreSettings settings;
        int result_code = parse_command_line(argc, argv, cli, settings);
        if (result_code != 0) {
            return result_code;
        }

        const auto pid = boost::this_process::get_id();
        const auto tid = std::this_thread::get_id();

        auto& log_settings = settings.log_settings;
        auto& node_settings = settings.node_settings;
        auto& server_settings = settings.server_settings;

        // Initialize logging with custom settings
        log::init(log_settings);

        // TODO(canepat): this could be an option in Silkworm logging facility
        rpc::Grpc2SilkwormLogGuard log_guard;

        const auto node_name{cmd::get_node_name_from_build_info(silkworm_get_buildinfo())};
        SILK_LOG << "BackEndKvServer build info: " << node_name;
        SILK_LOG << "BackEndKvServer library info: " << get_library_versions();
        SILK_LOG << "BackEndKvServer launched with chain id: " << node_settings.network_id
                 << " address: " << server_settings.address_uri()
                 << " contexts: " << server_settings.num_contexts();

        auto database_env = db::open_env(node_settings.chaindata_env_config);
        EthereumBackEnd backend{node_settings, &database_env};
        backend.set_node_name(node_name);

        SILK_INFO << "BackEndKvServer MDBX max readers: " << database_env.max_readers();

        rpc::BackEndKvServer server{server_settings, backend};
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

        SILK_LOG << "BackEndKvServer is now running [pid=" + std::to_string(pid) + ", main thread=" << tid << "]";
        server.join();

        SILK_LOG << "BackEndKvServer exiting [pid=" + std::to_string(pid) + ", main thread=" << tid << "]";
        return 0;
    } catch (const CLI::ParseError& pe) {
        return cli.exit(pe);
    } catch (const std::exception& e) {
        SILK_CRIT << "BackEndKvServer exiting due to exception: " << e.what();
        return -2;
    } catch (...) {
        SILK_CRIT << "BackEndKvServer exiting due to unexpected exception";
        return -3;
    }
}
