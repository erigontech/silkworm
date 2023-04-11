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
#include <stdexcept>
#include <string>

#include <CLI/CLI.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/process/environment.hpp>
#include <boost/system/error_code.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/buildinfo.h>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/context_pool_settings.hpp>
#include <silkworm/infra/rpc/common/util.hpp>
#include <silkworm/infra/rpc/server/server_context_pool.hpp>
#include <silkworm/node/backend/ethereum_backend.hpp>
#include <silkworm/node/backend/remote/backend_kv_server.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/mdbx.hpp>
#include <silkworm/sentry/rpc/client/sentry_client.hpp>

#include "common/common.hpp"
#include "common/db_max_readers_option.hpp"
#include "common/settings.hpp"
#include "common/shutdown_signal.hpp"

using namespace silkworm;
using namespace silkworm::cmd::common;

//! Assemble the relevant library version information
std::string get_library_versions() {
    std::string library_versions{"gRPC: "};
    library_versions.append(grpc::Version());
    library_versions.append(" MDBX: ");
    library_versions.append(mdbx::get_version().git.describe);
    return library_versions;
}

//! Standalone BackEndKV server settings
struct StandaloneBackEndKVSettings : public SilkwormSettings {
    bool simulate_state_changes{false};
};

//! Parse the command-line arguments into the BackEnd and KV server settings
int parse_command_line(int argc, char* argv[], CLI::App& app, StandaloneBackEndKVSettings& settings) {
    auto& log_settings = settings.log_settings;
    auto& node_settings = settings.node_settings;
    auto& server_settings = settings.server_settings;

    // Node options
    std::filesystem::path data_dir;
    add_option_data_dir(app, data_dir);

    std::string etherbase_address;
    add_option_etherbase(app, etherbase_address);

    uint32_t max_readers;
    add_option_db_max_readers(app, max_readers);

    // RPC Server options
    add_option_private_api_address(app, node_settings.private_api_addr);
    add_option_external_sentry_address(app, node_settings.external_sentry_addr);

    concurrency::ContextPoolSettings context_pool_settings;
    add_context_pool_options(app, context_pool_settings);

    // Logging options
    add_logging_options(app, log_settings);

    // Standalone BackEndKV server options
    app.add_flag("--simulate.state.changes", settings.simulate_state_changes, "Simulate state change notifications");

    app.parse(argc, argv);

    // Validate and assign settings
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
    server_settings.set_context_pool_settings(context_pool_settings);

    return 0;
}

class DummyServerCompletionQueue : public grpc::ServerCompletionQueue {
};

int main(int argc, char* argv[]) {
    using namespace silkworm::concurrency::awaitable_wait_for_one;

    CLI::App cli{"ETH BACKEND & KV server"};

    try {
        StandaloneBackEndKVSettings settings;
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
        log::set_thread_name("bekv_server");

        // TODO(canepat): this could be an option in Silkworm logging facility
        rpc::Grpc2SilkwormLogGuard log_guard;

        const auto node_name{get_node_name_from_build_info(silkworm_get_buildinfo())};
        SILK_LOG << "BackEndKvServer build info: " << node_name;
        SILK_LOG << "BackEndKvServer library info: " << get_library_versions();
        SILK_LOG << "BackEndKvServer launched with chaindata: " << node_settings.chaindata_env_config.path
                 << " address: " << node_settings.private_api_addr
                 << " contexts: " << server_settings.context_pool_settings().num_contexts;

        auto database_env = db::open_env(node_settings.chaindata_env_config);
        SILK_INFO << "BackEndKvServer MDBX max readers: " << database_env.max_readers();

        // Read chain config from database (this allows for custom config)
        db::ROTxn ro_txn{database_env};
        node_settings.chain_config = db::read_chain_config(ro_txn);
        if (!node_settings.chain_config.has_value()) {
            throw std::runtime_error("invalid chain config in database");
        }
        node_settings.network_id = node_settings.chain_config.value().chain_id;
        SILK_INFO << "BackEndKvServer chain from db: " << node_settings.network_id;

        // Load genesis hash
        node_settings.chain_config->genesis_hash = db::read_canonical_header_hash(ro_txn, 0);
        if (!node_settings.chain_config->genesis_hash.has_value()) {
            throw std::runtime_error("could not load genesis hash");
        }
        SILK_INFO << "BackEndKvServer genesis from db: " << to_hex(*node_settings.chain_config->genesis_hash);

        silkworm::rpc::ServerContextPool context_pool{
            server_settings.context_pool_settings(),
            [] { return std::make_unique<DummyServerCompletionQueue>(); },
        };

        // remote sentry client
        auto sentry_client = std::make_shared<silkworm::sentry::rpc::client::SentryClient>(
            node_settings.external_sentry_addr,
            *context_pool.next_context().client_grpc_context());

        EthereumBackEnd backend{
            node_settings,
            &database_env,
            sentry_client,
        };
        backend.set_node_name(node_name);

        rpc::BackEndKvServer server{server_settings, backend};
        server.build_and_start();

        // Standalone BackEndKV server has no staged loop, so this simulates periodic state changes
        boost::asio::steady_timer state_changes_timer{context_pool.next_io_context()};
        constexpr auto kStateChangeInterval{std::chrono::seconds(10)};
        constexpr silkworm::BlockNum kStartBlock{100'000'000};
        constexpr uint64_t kGasLimit{30'000'000};

        std::function<void(boost::system::error_code)> state_change_notification = [&](const boost::system::error_code& ec) {
            if (ec != boost::asio::error::operation_aborted) {
                static auto block_number = kStartBlock;
                backend.state_change_source()->start_new_batch(block_number, evmc::bytes32{}, {}, false);
                backend.state_change_source()->notify_batch(0, kGasLimit);
                SILK_INFO << "New batch notified for block: " << block_number;
                state_changes_timer.expires_at(std::chrono::steady_clock::now() + kStateChangeInterval);
                state_changes_timer.async_wait(state_change_notification);
                ++block_number;
            }
        };
        if (settings.simulate_state_changes) {
            state_changes_timer.expires_at(std::chrono::steady_clock::now() + kStateChangeInterval);
            state_changes_timer.async_wait(state_change_notification);
        }

        ShutdownSignal shutdown_signal{context_pool.next_io_context()};

        // Go!
        auto run_future = boost::asio::co_spawn(
            context_pool.next_io_context(),
            server.async_run() || shutdown_signal.wait(),
            boost::asio::use_future);
        context_pool.start();

        SILK_LOG << "BackEndKvServer is now running [pid=" + std::to_string(pid) + ", main thread=" << tid << "]";

        // Wait for shutdown_signal or an exception
        run_future.get();

        context_pool.stop();
        context_pool.join();

        backend.close();

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
