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

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#ifndef WIN32
#include <cxxabi.h>
#endif

#include <CLI/CLI.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/db/chain_head.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/node/node.hpp>
#include <silkworm/sentry/eth/status_data_provider.hpp>
#include <silkworm/sentry/sentry_client_factory.hpp>
#include <silkworm/sync/sync.hpp>

#include "common/common.hpp"
#include "common/db_checklist.hpp"
#include "common/node_options.hpp"
#include "common/rpcdaemon_options.hpp"
#include "common/sentry_options.hpp"
#include "common/settings.hpp"
#include "common/shutdown_signal.hpp"

namespace sw_db = silkworm::db;
namespace sw_log = silkworm::log;

using namespace silkworm;

using silkworm::BlockNum;
using silkworm::DataDirectory;
using silkworm::human_size;
using silkworm::cmd::common::add_logging_options;
using silkworm::cmd::common::add_node_options;
using silkworm::cmd::common::add_option_data_dir;
using silkworm::cmd::common::add_rpcdaemon_options;
using silkworm::cmd::common::add_sentry_options;
using silkworm::cmd::common::ShutdownSignal;
using silkworm::cmd::common::SilkwormSettings;

const char* current_exception_name() {
#ifdef WIN32
    return "<Exception name not supported on Windows>";
#else
    int status{0};
    return abi::__cxa_demangle(abi::__cxa_current_exception_type()->name(), nullptr, nullptr, &status);
#endif
}

struct PruneModeValidator : public CLI::Validator {
    explicit PruneModeValidator() {
        func_ = [](const std::string& value) -> std::string {
            if (value.find_first_not_of("hrtc") != std::string::npos) {
                return "Value " + value + " contains other characters other than h r t c";
            }
            return {};
        };
    }
};

void parse_silkworm_command_line(CLI::App& cli, int argc, char* argv[], SilkwormSettings& settings) {
    using namespace silkworm::cmd;

    auto& node_settings = settings.node_settings;

    std::filesystem::path data_dir_path;
    add_option_data_dir(cli, data_dir_path);

    // Node settings
    add_node_options(cli, node_settings);

    // Sentry settings
    add_sentry_options(cli, settings.sentry_settings);

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
    add_logging_options(cli, settings.log_settings);

    // RpcDaemon settings
    add_rpcdaemon_options(cli, settings.rpcdaemon_settings);

    cli.parse(argc, argv);

    // Validate and assign settings

    const size_t chaindata_page_size = node_settings.chaindata_env_config.page_size;
    if ((chaindata_page_size & (chaindata_page_size - 1)) != 0) {
        throw std::invalid_argument("--chaindata.pagesize is not a power of 2");
    }

    const size_t mdbx_max_size_hard_limit = chaindata_page_size * sw_db::kMdbxMaxPages;
    if (node_settings.chaindata_env_config.max_size > mdbx_max_size_hard_limit) {
        throw std::invalid_argument("--chaindata.maxsize exceeds max allowed size by page size i.e" +
                                    human_size(mdbx_max_size_hard_limit));
    }

    if (node_settings.chaindata_env_config.growth_size > (mdbx_max_size_hard_limit / /* two increments ?*/ 2u)) {
        throw std::invalid_argument("--chaindata.growthsize must be <=" + human_size(mdbx_max_size_hard_limit / 2));
    }

    node_settings.data_directory = std::make_unique<DataDirectory>(data_dir_path, /*create=*/true);

    // Parse prune mode
    sw_db::PruneDistance olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces;
    if (cli["--prune.h.older"]->count()) olderHistory.emplace(cli["--prune.h.older"]->as<BlockNum>());
    if (cli["--prune.r.older"]->count()) olderReceipts.emplace(cli["--prune.r.older"]->as<BlockNum>());
    if (cli["--prune.s.older"]->count()) olderSenders.emplace(cli["--prune.s.older"]->as<BlockNum>());
    if (cli["--prune.t.older"]->count()) olderTxIndex.emplace(cli["--prune.t.older"]->as<BlockNum>());
    if (cli["--prune.c.older"]->count()) olderCallTraces.emplace(cli["--prune.c.older"]->as<BlockNum>());

    sw_db::PruneThreshold beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces;
    if (cli["--prune.h.before"]->count()) beforeHistory.emplace(cli["--prune.h.before"]->as<BlockNum>());
    if (cli["--prune.r.before"]->count()) beforeReceipts.emplace(cli["--prune.r.before"]->as<BlockNum>());
    if (cli["--prune.s.before"]->count()) beforeSenders.emplace(cli["--prune.s.before"]->as<BlockNum>());
    if (cli["--prune.t.before"]->count()) beforeTxIndex.emplace(cli["--prune.t.before"]->as<BlockNum>());
    if (cli["--prune.c.before"]->count()) beforeCallTraces.emplace(cli["--prune.c.before"]->as<BlockNum>());

    node_settings.prune_mode =
        sw_db::parse_prune_mode(prune_mode,
                                olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces, beforeHistory,
                                beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces);

    auto& snapshot_settings = node_settings.snapshot_settings;
    snapshot_settings.repository_dir = node_settings.data_directory->snapshots().path();
    snapshot_settings.bittorrent_settings.repository_path = snapshot_settings.repository_dir;
}

// main
int main(int argc, char* argv[]) {
    using namespace boost::placeholders;
    using namespace std::chrono;
    using namespace silkworm::concurrency::awaitable_wait_for_one;
    using namespace silkworm::concurrency::awaitable_wait_for_all;

    std::set_terminate([]() {
        try {
            auto exc = std::current_exception();
            if (exc) {
                std::rethrow_exception(exc);
            }
        } catch (const std::exception& e) {
            SILK_CRIT << "Silkworm terminating due to exception: " << e.what();
        } catch (...) {
            SILK_CRIT << "Silkworm terminating due to unexpected exception: " << current_exception_name();
        }
        std::abort();
    });

    CLI::App cli("Silkworm node");
    cli.get_formatter()->column_width(50);

    try {
        SilkwormSettings settings;
        parse_silkworm_command_line(cli, argc, argv, settings);

        auto& node_settings = settings.node_settings;

        // Initialize logging with cli settings
        sw_log::init(settings.log_settings);
        sw_log::set_thread_name("main-thread");

        // Output BuildInfo
        const auto build_info{silkworm_get_buildinfo()};
        node_settings.build_info = make_application_info(build_info);

        sw_log::Info("Silkworm", build_info_as_log_args(build_info));

        // Output mdbx build info
        auto mdbx_ver{mdbx::get_version()};
        auto mdbx_bld{mdbx::get_build()};
        sw_log::Debug("libmdbx",
                      {"version", mdbx_ver.git.describe, "build", mdbx_bld.target, "compiler", mdbx_bld.compiler});

        // Prepare database for takeoff
        cmd::common::run_db_checklist(node_settings);

        mdbx::env_managed chaindata_env = db::open_env(node_settings.chaindata_env_config);

        silkworm::rpc::ClientContextPool context_pool{
            settings.node_settings.server_settings.context_pool_settings,
        };

        // Sentry: the peer-2-peer proxy server
        settings.sentry_settings.client_id = sentry::Sentry::make_client_id(*build_info);
        settings.sentry_settings.data_dir_path = node_settings.data_directory->path();
        settings.sentry_settings.network_id = node_settings.network_id;

        auto chain_head_provider = [db_access = db::ROAccess{chaindata_env}] {
            return db::read_chain_head(db_access);
        };
        sentry::eth::StatusDataProvider eth_status_data_provider{std::move(chain_head_provider), node_settings.chain_config.value()};

        auto [sentry_client, sentry_server] = sentry::SentryClientFactory::make_sentry(
            std::move(settings.sentry_settings),
            settings.node_settings.remote_sentry_addresses,
            context_pool.as_executor_pool(),
            context_pool,
            eth_status_data_provider.to_factory_function());
        auto embedded_sentry_run_if_needed = [](auto server) -> Task<void> {
            if (server) {
                co_await server->run();
            }
        };

        // Execution: the execution layer engine
        silkworm::node::Node execution_node{context_pool.any_executor(), settings.node_settings, sentry_client, mdbx::env{chaindata_env}};
        execution::api::DirectClient& execution_client{execution_node.execution_direct_client()};

        // ChainSync: the chain synchronization process based on the consensus protocol
        chainsync::EngineRpcSettings rpc_settings{
            .engine_end_point = settings.rpcdaemon_settings.engine_end_point,
            .engine_ifc_log_settings = settings.rpcdaemon_settings.engine_ifc_log_settings,
            .private_api_addr = settings.rpcdaemon_settings.private_api_addr,
            .log_verbosity = settings.log_settings.log_verbosity,
            .wait_mode = settings.rpcdaemon_settings.context_pool_settings.wait_mode,
            .jwt_secret_file = settings.rpcdaemon_settings.jwt_secret_file,
        };
        chainsync::Sync chain_sync_process{
            context_pool.any_executor(),
            mdbx::env{chaindata_env},
            execution_client,
            sentry_client,
            *node_settings.chain_config,
            rpc_settings};
        // Note: temp code until chainsync::Sync becomes a part of Node
        auto chain_sync_process_run = [&execution_node](chainsync::Sync& sync) -> Task<void> {
            co_await execution_node.wait_for_setup();
            co_await sync.async_run();
        };

        auto tasks =
            execution_node.run() &&
            embedded_sentry_run_if_needed(sentry_server) &&
            chain_sync_process_run(chain_sync_process);

        // Trap OS signals
        ShutdownSignal shutdown_signal{context_pool.any_executor()};

        // Go!
        auto run_future = boost::asio::co_spawn(
            context_pool.any_executor(),
            std::move(tasks) || shutdown_signal.wait(),
            boost::asio::use_future);
        context_pool.start();
        sw_log::Info() << "Silkworm is now running";

        // Wait for shutdown signal or an exception from tasks
        run_future.get();

        // Graceful exit after user shutdown signal
        sw_log::Info() << "Exiting Silkworm";
        return 0;
    } catch (const CLI::ParseError& ex) {
        // Let CLI11 handle any error occurred parsing command-line args
        return cli.exit(ex);
    } catch (const std::exception& ex) {
        // Any exception during run leads to termination
        sw_log::Critical("Unrecoverable failure: exit", {"error", ex.what()});
        return -1;
    } catch (...) {
        // Any unknown exception during run leads to termination
        sw_log::Critical("Unrecoverable failure: exit", {"error", "unexpected exception"});
        return -2;
    }
}
