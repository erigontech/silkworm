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
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>
#include <silkworm/node/backend/ethereum_backend.hpp>
#include <silkworm/node/backend/remote/backend_kv_server.hpp>
#include <silkworm/node/common/settings.hpp>
#include <silkworm/node/db/stages.hpp>
#include <silkworm/node/snapshot/sync.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>
#include <silkworm/sync/block_exchange.hpp>
#include <silkworm/sync/sentry_client.hpp>
#include <silkworm/sync/sync_engine_pow.hpp>

#include "common/common.hpp"
#include "common/settings.hpp"

using namespace silkworm;
using namespace silkworm::cmd::common;

// progress log
class ResourceUsageLog : public ActiveComponent {
    NodeSettings& node_settings_;

  public:
    explicit ResourceUsageLog(NodeSettings& settings) : node_settings_{settings} {}

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

void parse_silkworm_command_line(CLI::App& cli, int argc, char* argv[], SilkwormCoreSettings& settings) {
    using namespace silkworm::cmd;

    auto& node_settings = settings.node_settings;

    // Node settings
    std::filesystem::path data_dir_path;
    std::string chaindata_max_size_str{human_size(node_settings.chaindata_env_config.max_size)};
    std::string chaindata_growth_size_str{human_size(node_settings.chaindata_env_config.growth_size)};
    std::string chaindata_page_size_str{human_size(node_settings.chaindata_env_config.page_size)};
    std::string batch_size_str{human_size(node_settings.batch_size)};
    std::string etl_buffer_size_str{human_size(node_settings.etl_buffer_size)};
    add_option_data_dir(cli, data_dir_path);

    cli.add_flag("--chaindata.exclusive", node_settings.chaindata_env_config.exclusive,
                 "Chaindata database opened in exclusive mode");
    cli.add_flag("--chaindata.readahead", node_settings.chaindata_env_config.read_ahead,
                 "Chaindata database enable readahead");
    cli.add_flag("--chaindata.writemap", node_settings.chaindata_env_config.write_map,
                 "Chaindata database enable writemap");

    cli.add_option("--chaindata.growthsize", chaindata_growth_size_str, "Chaindata database growth size.")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("64MB"));
    cli.add_option("--chaindata.pagesize", chaindata_page_size_str, "Chaindata database page size. A power of 2")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("256B", {"65KB"}));
    cli.add_option("--chaindata.maxsize", chaindata_max_size_str, "Chaindata database max size.")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("32MB", {"128TB"}));

    cli.add_option("--batchsize", batch_size_str, "Batch size for stage execution")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("64MB", {"16GB"}));
    cli.add_option("--etl.buffersize", etl_buffer_size_str, "Buffer size for ETL operations")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("64MB", {"1GB"}));

    add_option_private_api_address(cli, node_settings.private_api_addr);

    // Sentry settings
    add_option_external_sentry_address(cli, node_settings.external_sentry_addr);

    add_option_sentry_api_address(cli, node_settings.sentry_api_addr);

    cli.add_option("--sync.loop.throttle", node_settings.sync_loop_throttle_seconds,
                   "Sets the minimum delay between sync loop starts (in seconds)")
        ->capture_default_str()
        ->check(CLI::Range(1u, 7200u));

    cli.add_option("--sync.loop.log.interval", node_settings.sync_loop_log_interval_seconds,
                   "Sets the interval between sync loop logs (in seconds)")
        ->capture_default_str()
        ->check(CLI::Range(10u, 600u));

    cli.add_flag("--fakepow", node_settings.fake_pow, "Disables proof-of-work verification");

    // Chain options
    add_option_chain(cli, node_settings.network_id);

    // Prune options
    std::string prune_mode;
    auto& prune_opts = *cli.add_option_group("Prune", "Prune options to delete ancient data from DB");
    prune_opts
        .add_option("--prune", prune_mode,
                    "Delete data older than 90K blocks (see \"--prune.*.older\" for different height)\n"
                    "h - prune history (ChangeSets, HistoryIndices - used by historical state access)\n"
                    "r - prune receipts (Receipts, Logs, LogTopicIndex, LogAddressIndex - used by eth_getLogs and "
                    "similar RPC methods)\n"
                    "s - prune senders recovered\n"
                    "t - prune transaction by it's hash index\n"
                    "c - prune call traces (used by trace_* methods)\n"
                    "If item is NOT in the list - means NO pruning for this data.\n"
                    "Example: --prune=hrtc (default: none)")
        ->capture_default_str()
        ->check(PruneModeValidator());

    prune_opts.add_option("--prune.h.older", "Override default 90k blocks of history to prune")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.r.older", "Override default 90k blocks of receipts to prune")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.s.older", "Override default 90k blocks of senders to prune")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.t.older", "Override default 90k blocks of transactions to prune")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.c.older", "Override default 90k blocks of call traces to prune")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.h.before", "Prune history data before this block")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.r.before", "Prune receipts data before this block")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.s.before", "Prune senders data before this block")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.t.before", "Prune transactions data before this block")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.c.before", "Prune call traces data before this block")
        ->check(CLI::Range(0u, UINT32_MAX));

    // Logging options
    auto& log_settings = settings.log_settings;
    add_logging_options(cli, log_settings);

    // RPC server options
    auto& server_settings = settings.server_settings;

    uint32_t num_contexts;
    add_option_num_contexts(cli, num_contexts);

    silkworm::rpc::WaitMode wait_mode;
    add_option_wait_mode(cli, wait_mode);

    // Snapshot&Bittorrent options
    auto& snapshot_settings = settings.snapshot_settings;
    add_snapshot_options(cli, snapshot_settings);

    cli.parse(argc, argv);

    // Validate and assign settings
    const auto chaindata_page_size{parse_size(chaindata_page_size_str)};
    if (!chaindata_page_size.has_value() || (*chaindata_page_size & (*chaindata_page_size - 1)) != 0) {
        throw std::invalid_argument("--chaindata.pagesize is not a power of 2");
    }
    node_settings.chaindata_env_config.page_size = chaindata_page_size.value();
    const auto mdbx_max_size_hard_limit{chaindata_page_size.value() * db::kMdbxMaxPages};
    const auto chaindata_max_size{parse_size(chaindata_max_size_str)};
    if (chaindata_max_size.value() > mdbx_max_size_hard_limit) {
        throw std::invalid_argument("--chaindata.maxsize exceeds max allowed size by page size i.e" +
                                    human_size(mdbx_max_size_hard_limit));
    }
    const auto chaindata_growth_size{parse_size(chaindata_growth_size_str)};
    if (chaindata_growth_size > (mdbx_max_size_hard_limit / /* two increments ?*/ 2u)) {
        throw std::invalid_argument("--chaindata.growthsize must be <=" + human_size(mdbx_max_size_hard_limit / 2));
    }

    node_settings.data_directory = std::make_unique<DataDirectory>(data_dir_path, /*create=*/true);
    node_settings.chaindata_env_config.max_size = chaindata_max_size.value();
    node_settings.chaindata_env_config.growth_size = chaindata_growth_size.value();

    node_settings.batch_size = parse_size(batch_size_str).value();
    node_settings.etl_buffer_size = parse_size(etl_buffer_size_str).value();

    // Parse prune mode
    db::PruneDistance olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces;
    if (cli["--prune.h.older"]->count()) olderHistory.emplace(cli["--prune.h.older"]->as<BlockNum>());
    if (cli["--prune.r.older"]->count()) olderReceipts.emplace(cli["--prune.r.older"]->as<BlockNum>());
    if (cli["--prune.s.older"]->count()) olderSenders.emplace(cli["--prune.s.older"]->as<BlockNum>());
    if (cli["--prune.t.older"]->count()) olderTxIndex.emplace(cli["--prune.t.older"]->as<BlockNum>());
    if (cli["--prune.c.older"]->count()) olderCallTraces.emplace(cli["--prune.c.older"]->as<BlockNum>());

    db::PruneThreshold beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces;
    if (cli["--prune.h.before"]->count()) beforeHistory.emplace(cli["--prune.h.before"]->as<BlockNum>());
    if (cli["--prune.r.before"]->count()) beforeReceipts.emplace(cli["--prune.r.before"]->as<BlockNum>());
    if (cli["--prune.s.before"]->count()) beforeSenders.emplace(cli["--prune.s.before"]->as<BlockNum>());
    if (cli["--prune.t.before"]->count()) beforeTxIndex.emplace(cli["--prune.t.before"]->as<BlockNum>());
    if (cli["--prune.c.before"]->count()) beforeCallTraces.emplace(cli["--prune.c.before"]->as<BlockNum>());

    node_settings.prune_mode =
        db::parse_prune_mode(prune_mode,  //
                             olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces, beforeHistory,
                             beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces);

    server_settings.set_address_uri(node_settings.private_api_addr);
    server_settings.set_num_contexts(num_contexts);
    server_settings.set_wait_mode(wait_mode);

    snapshot_settings.bittorrent_settings.repository_path = snapshot_settings.repository_dir;
}

// main
int main(int argc, char* argv[]) {
    using namespace boost::placeholders;
    using namespace std::chrono;

    CLI::App cli("Silkworm node");
    cli.get_formatter()->column_width(50);

    try {
        SilkwormCoreSettings settings;
        parse_silkworm_command_line(cli, argc, argv, settings);

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
        run_preflight_checklist(node_settings);  // Prepare database for takeoff

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
        const auto node_name{get_node_name_from_build_info(build_info)};
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
