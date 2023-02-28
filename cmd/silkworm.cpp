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

#include <silkworm/buildinfo.h>
#include <silkworm/core/common/mem_usage.hpp>
#include <silkworm/node/backend/backend_kv_server.hpp>
#include <silkworm/node/common/log.hpp>
#include <silkworm/node/common/settings.hpp>
#include <silkworm/node/common/stopwatch.hpp>
#include <silkworm/node/concurrency/signal_handler.hpp>
#include <silkworm/node/db/stages.hpp>
#include <silkworm/node/downloader/block_exchange.hpp>
#include <silkworm/node/downloader/sentry_client.hpp>
#include <silkworm/node/downloader/sync_engine_pow.hpp>
#include <silkworm/node/snapshot/sync.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>

#include "common.hpp"

using namespace silkworm;

// progress log
class ResourceUsageLog : public ActiveComponent {
    NodeSettings& node_settings_;

  public:
    ResourceUsageLog(NodeSettings& settings) : node_settings_{settings} {}

    void execution_loop() override {  // todo: this is only a trick, instead use asio timers
        using namespace std::chrono;
        log::set_thread_name("progress-log  ");
        auto start_time = steady_clock::now();
        auto last_update = start_time;
        while (!is_stopping()) {
            std::this_thread::sleep_for(500ms);

            auto now = steady_clock::now();
            if (now - last_update > 300s) {
                log::Info("Resource usage",
                          {"mem", human_size(get_mem_usage()),
                           "chain", human_size(node_settings_.data_directory->chaindata().size()),
                           "etl-tmp", human_size(node_settings_.data_directory->etl().size()),
                           "uptime", StopWatch::format(now - start_time)});
                last_update = now;
            }
        }
    }
};

// main
int main(int argc, char* argv[]) {
    using namespace boost::placeholders;
    using namespace std::chrono;

    CLI::App cli("Silkworm node");
    cli.get_formatter()->column_width(50);

    try {
        cmd::SilkwormCoreSettings settings;
        cmd::parse_silkworm_command_line(cli, argc, argv, settings);

        auto& node_settings = settings.node_settings;
        auto& snapshot_settings = settings.snapshot_settings;

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

        PreverifiedHashes::load(node_settings.chain_config->chain_id);

        // Start boost asio
        using asio_guard_type = boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;
        auto asio_guard = std::make_unique<asio_guard_type>(node_settings.asio_context.get_executor());
        std::thread asio_thread{[&node_settings]() -> void {
            log::set_thread_name("Asio");
            log::Trace("Boost Asio", {"state", "started"});
            node_settings.asio_context.run();
            log::Trace("Boost Asio", {"state", "stopped"});
        }};

        // Resource usage logging
        ResourceUsageLog resource_usage_log(node_settings);
        auto resource_usage_logging = std::thread([&resource_usage_log]() { resource_usage_log.execution_loop(); });

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

        if (snapshot_settings.enabled) {
            db::RWTxn rw_txn{chaindata_db};

            // Snapshot sync - download chain from peers using snapshot files
            SnapshotSync snapshot_sync{snapshot_settings, node_settings.chain_config.value()};
            snapshot_sync.download_and_index_snapshots(rw_txn);
        } else {
            log::Info() << "Snapshot sync disabled, no snapshot must be downloaded";
        }

        // ExecutionEngine executes transactions and builds state validating chain slices
        silkworm::stagedsync::ExecutionEngine execution{node_settings, db::RWAccess{chaindata_db}};

        // ConsensusEngine drives headers and bodies sync, implementing fork choice rules
        silkworm::chainsync::PoWSync sync{block_exchange, execution};

        // Trap OS signals
        SignalHandler::init([&](int) {
            log::Info() << "Requesting termination\n";
            sync.stop();
        });

        // Sync main loop
        sync.execution_loop();  // currently sync & execution are on the same process, sync calls execution so due to
                                // limitations related to the db rw tx owned by execution they must run on the same thread

        /*
        if (is_pow(node_settings.chain_config)) {
            silkworm::stagedsync::ExecutionEngine execution{node_settings, db::RWAccess{chaindata_db}};

            chainsync::pow::SyncEngine sync(block_exchange, execution);

            SignalHandler::init([&](int) { sync.stop(); });

            sync.execution_loop();
        }
        else (is_pos(node_settings.chain_config)) {
            ExecutionServer exec_server;

            ExecutionClient exec_client(exec_server);

            chainsync::pos::SyncEngine sync(block_exchange, exec_client);
            auto sync_running = std::thread([&sync]() { sync.execution_loop(); });

            ExtConsensusClient cons(sync);
            auto cons_running = std::thread([&cons]() { cons.execution_loop(); });

            SignalHandler::init([&](int) { exec_server.stop(); });

            exec_server.execution_loop();  // MDBX wr thread
        }
        else
            throw std::invalid_argument("Invalid chain config");
        */

        // Close all resources
        backend.close();
        rpc_server.shutdown();
        rpc_server.join();

        block_exchange.stop();
        sentry.stop();
        sync.stop();
        resource_usage_log.stop();
        block_downloading.join();
        message_receiving.join();
        stats_receiving.join();
        resource_usage_logging.join();

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
