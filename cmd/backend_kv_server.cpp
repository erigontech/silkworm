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

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/process/environment.hpp>
#include <CLI/CLI.hpp>
#include <magic_enum.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/backend/ethereum_backend.hpp>
#include <silkworm/chain/config.hpp>
#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/rpc/backend_kv_server.hpp>
#include <silkworm/rpc/util.hpp>

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

std::string get_library_versions() {
    std::string library_versions{"gRPC: "};
    library_versions.append(grpc::Version());
    library_versions.append(" MDBX: ");
    library_versions.append(mdbx::get_version().git.describe);
    return library_versions;
}

struct BackEndKvSettings {
    silkworm::log::Settings log_settings;
    silkworm::NodeSettings node_settings;
    silkworm::rpc::ServerConfig server_settings;
};

int parse_command_line(int argc, char* argv[], BackEndKvSettings& settings) {
    CLI::App app{"ETHBACKEND & KV servers"};

    try {
        auto& log_settings = settings.log_settings;
        auto& node_settings = settings.node_settings;
        auto& server_settings = settings.server_settings;

        std::string data_dir{silkworm::DataDirectory::get_default_storage_path().string()};
        std::string etherbase_address{""};
        uint32_t num_contexts{std::thread::hardware_concurrency() / 2};
        app.add_option("--datadir", data_dir, "The path to data directory", true);
        app.add_option("--etherbase", etherbase_address, "The chain identifier as string", true);
        // TODO(canepat) add check on etherbase using EthAddressValidator [TBD]
        app.add_option("--numContexts", num_contexts, "The number of running contexts", true);

        // RPC Server options
        app.add_option("--private.api.addr", node_settings.private_api_addr,
            "Private API network address to serve remote database interface\n"
            "An empty string means to not start the listener\n"
            "Use the endpoint form i.e. ip-address:port\n"
            "DO NOT EXPOSE TO THE INTERNET",
            true);
        // TODO(canepat) add check on private.api.addr using IPEndPointValidator
        app.add_option("--sentry.api.addr", node_settings.sentry_api_addr, "Sentry api endpoint", true);
        // TODO(canepat) add check on sentry_api_addr using IPEndPointValidator

        // Chain options
        auto& chain_opts = *app.add_option_group("Chain", "Chain selection options");
        auto chain_name = chain_opts.add_option("--chain", "Name of the network to join (default: \"mainnet\")")
            ->transform(CLI::Transformer(silkworm::get_known_chains_map(), CLI::ignore_case));
        chain_opts.add_option("--networkid", node_settings.network_id,
            "Explicitly set network id\n"
            "For known networks: use --chain <testnet_name> instead",
            true)
            ->excludes(chain_name);

        // Logging options
        auto& log_opts = *app.add_option_group("Log", "Logging options");
        log_opts.add_option("--log.verbosity", log_settings.log_verbosity, "Sets log verbosity", true)
            ->check(CLI::Range(static_cast<uint32_t>(silkworm::log::Level::kCritical), static_cast<uint32_t>(silkworm::log::Level::kTrace)))
            ->default_val(std::to_string(static_cast<uint32_t>(silkworm::log::Level::kCritical)));
        log_opts.add_flag("--log.stdout", log_settings.log_std_out, "Outputs to std::out instead of std::err");
        log_opts.add_flag("--log.nocolor", log_settings.log_nocolor, "Disable colors on log lines")
            ->default_val(std::to_string(true));
        log_opts.add_flag("--log.utc", log_settings.log_utc, "Prints log timings in UTC");
        log_opts.add_flag("--log.threads", log_settings.log_threads, "Prints thread ids")
            ->default_val(std::to_string(true));
        log_opts.add_option("--log.file", log_settings.log_file, "Tee all log lines to given file name");

        app.parse(argc, argv);

        if (chain_name->count()) {
            node_settings.network_id = chain_name->as<uint32_t>();
        }
        const silkworm::ChainConfig* chain_config = silkworm::lookup_chain_config(node_settings.network_id);
        if (chain_config == nullptr) {
            SILK_CRIT << "Unknown chain identifier: " << node_settings.network_id;
            return -1;
        }
        node_settings.chain_config = *chain_config;

        if (!etherbase_address.empty()) {
            const auto etherbase = silkworm::from_hex(etherbase_address);
            if (!etherbase) {
                SILK_CRIT << "Invalid etherbase address: " << etherbase_address;
                return -1;
            }
            node_settings.etherbase = silkworm::to_evmc_address(etherbase.value());
        }

        node_settings.data_directory = std::make_unique<silkworm::DataDirectory>(data_dir, /*create=*/false);
        node_settings.chaindata_env_config = silkworm::db::EnvConfig{
            node_settings.data_directory->chaindata().path().string(),
            /*create=*/false,
            /*readonly=*/true
        };

        server_settings.set_address_uri(node_settings.private_api_addr);
        server_settings.set_num_contexts(num_contexts);

        return 0;
    } catch (const CLI::ParseError &pe) {
        return app.exit(pe);
    }
}

int main(int argc, char* argv[]) {
    BackEndKvSettings settings;
    int result_code = parse_command_line(argc, argv, settings);
    if (result_code != 0) {
        return result_code;
    }

    const auto pid = boost::this_process::get_id();
    const auto tid = std::this_thread::get_id();

    auto& log_settings = settings.log_settings;
    auto& node_settings = settings.node_settings;
    auto& server_settings = settings.server_settings;

    // Initialize logging settings
    silkworm::log::init(log_settings);

    //TODO(canepat): this could be an option in Silkworm logging facility
    silkworm::rpc::Grpc2SilkwormLogGuard log_guard;

    const auto node_name{get_node_name_from_build_info()};
    SILK_LOG << "BackEndKvServer build info: " << node_name << " " << get_library_versions();

    try {
        SILK_LOG << "BackEndKvServer launched with address: " << server_settings.address_uri() << ", contexts: " << server_settings.num_contexts();

        auto database_env = silkworm::db::open_env(node_settings.chaindata_env_config);
        silkworm::EthereumBackEnd backend{node_settings, &database_env};
        backend.set_node_name(node_name);

        silkworm::rpc::BackEndKvServer server{server_settings, backend};
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
