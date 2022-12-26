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

#include <stdexcept>

#include <CLI/CLI.hpp>

#include <silkworm/backend/backend_kv_server.hpp>
#include <silkworm/buildinfo.h>
#include <silkworm/common/log.hpp>
#include <silkworm/common/mem_usage.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/concurrency/signal_handler.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/downloader/block_exchange.hpp>
#include <silkworm/downloader/sentry_client.hpp>
#include <silkworm/stagedsync/execution_engine.hpp>

#include "common.hpp"
#include "silkworm/downloader/sync_engine.hpp"

using namespace silkworm;

int main(int argc, char* argv[]) {
    using namespace boost::placeholders;
    using namespace std::chrono;

    CLI::App cli("Silkworm node");
    cli.get_formatter()->column_width(50);
    auto start_time = steady_clock::now();

    try {
        cmd::SilkwormCoreSettings settings;
        cmd::parse_silkworm_command_line(cli, argc, argv, settings);

        auto& node_settings = settings.node_settings;

        // Trap OS signals
        SignalHandler::init();

        // Initialize logging with cli settings
        log::init(settings.log_settings);
        log::set_thread_name("main");

        // Output BuildInfo
        const auto build_info{silkworm_get_buildinfo()};
        node_settings.build_info =
            "version=" + std::string(build_info->git_branch) + std::string(build_info->project_version) +
            "build=" + std::string(build_info->system_name) + "-" + std::string(build_info->system_processor) +
            " " + std::string(build_info->build_type) +
            "compiler=" + std::string(build_info->compiler_id) +
            " " + std::string(build_info->compiler_version);

        log::Message(
            "Silkworm",
            {"version", std::string(build_info->git_branch) + std::string(build_info->project_version),
             "build",
             std::string(build_info->system_name) + "-" + std::string(build_info->system_processor) + " " +
                 std::string(build_info->build_type),
             "compiler",
             std::string(build_info->compiler_id) + " " + std::string(build_info->compiler_version)});

        // Output mdbx build info
        auto mdbx_ver{mdbx::get_version()};
        auto mdbx_bld{mdbx::get_build()};
        log::Message("libmdbx",
                     {"version", mdbx_ver.git.describe, "build", mdbx_bld.target, "compiler", mdbx_bld.compiler});

        // Check db
        cmd::run_preflight_checklist(node_settings);  // Prepare database for takeoff

        auto chaindata_db{silkworm::db::open_env(node_settings.chaindata_env_config)};

        // Start boost asio
        using asio_guard_type = boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;
        auto asio_guard = std::make_unique<asio_guard_type>(node_settings.asio_context.get_executor());
        std::thread asio_thread{[&node_settings]() -> void {
            log::set_thread_name("Asio");
            log::Trace("Boost Asio", {"state", "started"});
            node_settings.asio_context.run();
            log::Trace("Boost Asio", {"state", "stopped"});
        }};

        // BackEnd & KV server
        const auto node_name{silkworm::cmd::get_node_name_from_build_info(build_info)};
        silkworm::EthereumBackEnd backend{node_settings, &chaindata_db};
        backend.set_node_name(node_name);

        silkworm::rpc::BackEndKvServer rpc_server{settings.server_settings, backend};
        rpc_server.build_and_start();

        // Sentry client - connects to sentry
        SentryClient sentry{node_settings.external_sentry_addr, db::ROAccess{chaindata_db},
                            node_settings.chain_config.value()};
        auto message_receiving = std::thread([&sentry]() { sentry.execution_loop(); });
        auto stats_receiving = std::thread([&sentry]() { sentry.stats_receiving_loop(); });

        // BlockExchange - download headers and bodies from remote peers using the sentry
        BlockExchange block_exchange{sentry, db::ROAccess{chaindata_db}, node_settings.chain_config.value()};
        auto block_downloading = std::thread([&block_exchange]() { block_exchange.execution_loop(); });

        // ExecutionEngine executes transactions and builds state validating chain slices
        silkworm::stagedsync::ExecutionEngine execution{node_settings, db::RWAccess{chaindata_db}};

        // ConsensusEngine drives headers and bodies sync, implementing fork choice rules
        silkworm::chainsync::SyncEngine sync{
            node_settings, db::ROAccess{chaindata_db}, block_exchange, execution};
        auto chain_syncing = std::thread([&sync]() { sync.execution_loop(); });

        // Keep waiting till user stops logging resource usage
        auto last_update = steady_clock::now();
        while (!SignalHandler::signalled()) {
            std::this_thread::sleep_for(500ms);

            auto now = steady_clock::now();
            if (now - last_update > 300s) {
                log::Info("Resource usage",
                          {"mem", human_size(get_mem_usage()),
                           "chain", human_size(node_settings.data_directory->chaindata().size()),
                           "etl-tmp", human_size(node_settings.data_directory->etl().size()),
                           "uptime", StopWatch::format(now - start_time)});
                last_update = now;
            }
        }

        // Close all resources
        backend.close();
        rpc_server.shutdown();
        rpc_server.join();

        block_exchange.stop();
        sentry.stop();
        sync.stop();
        block_downloading.join();
        message_receiving.join();
        stats_receiving.join();
        chain_syncing.join();

        asio_guard.reset();
        asio_thread.join();

        log::Message() << "Closing database chaindata path: " << node_settings.data_directory->chaindata().path();
        chaindata_db.close();
        log::Message() << "Database closed";

        return 0;

    } catch (const CLI::ParseError& ex) {
        return cli.exit(ex);
    } catch (const std::runtime_error& ex) {
        log::Error() << ex.what();
        return -1;
    } catch (const std::invalid_argument& ex) {
        std::cerr << "\tInvalid argument :" << ex.what() << "\n"
                  << std::endl;
        return -3;
    } catch (const std::exception& ex) {
        std::cerr << "\tUnexpected error : " << ex.what() << "\n"
                  << std::endl;
        return -4;
    } catch (...) {
        std::cerr << "\tUnexpected undefined error\n"
                  << std::endl;
        return -99;
    }
}
