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
#include <regex>
#include <stdexcept>
#include <string>
#include <utility>

#include <CLI/CLI.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/buildinfo.h>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/os.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/grpc/server/server_context_pool.hpp>
#include <silkworm/node/db/eth_status_data_provider.hpp>
#include <silkworm/node/node.hpp>
#include <silkworm/sentry/api/api_common/sentry_client.hpp>
#include <silkworm/sentry/grpc/client/sentry_client.hpp>
#include <silkworm/sentry/multi_sentry_client.hpp>
#include <silkworm/sentry/sentry.hpp>
#include <silkworm/sentry/session_sentry_client.hpp>
#include <silkworm/sync/sync.hpp>

#include "common/common.hpp"
#include "common/db_checklist.hpp"
#include "common/human_size_parser_validator.hpp"
#include "common/node_options.hpp"
#include "common/rpcdaemon_options.hpp"
#include "common/sentry_options.hpp"
#include "common/settings.hpp"
#include "common/shutdown_signal.hpp"
#include "common/snapshot_options.hpp"

namespace sw_db = silkworm::db;
namespace sw_log = silkworm::log;

using namespace silkworm;

using silkworm::ActiveComponent;
using silkworm::BlockExchange;
using silkworm::BlockNum;
using silkworm::DataDirectory;
using silkworm::human_size;
using silkworm::lookup_known_chain;
using silkworm::NodeSettings;
using silkworm::parse_size;
using silkworm::PreverifiedHashes;
using silkworm::StopWatch;
using silkworm::cmd::common::add_context_pool_options;
using silkworm::cmd::common::add_logging_options;
using silkworm::cmd::common::add_node_options;
using silkworm::cmd::common::add_option_chain;
using silkworm::cmd::common::add_option_data_dir;
using silkworm::cmd::common::add_option_private_api_address;
using silkworm::cmd::common::add_option_remote_sentry_addresses;
using silkworm::cmd::common::add_rpcdaemon_options;
using silkworm::cmd::common::add_sentry_options;
using silkworm::cmd::common::add_snapshot_options;
using silkworm::cmd::common::get_node_name_from_build_info;
using silkworm::cmd::common::HumanSizeParserValidator;
using silkworm::cmd::common::ShutdownSignal;
using silkworm::cmd::common::SilkwormSettings;

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

    std::string chaindata_max_size_str{human_size(node_settings.chaindata_env_config.max_size)};
    std::string chaindata_growth_size_str{human_size(node_settings.chaindata_env_config.growth_size)};
    std::string chaindata_page_size_str{human_size(node_settings.chaindata_env_config.page_size)};
    std::string batch_size_str{human_size(node_settings.batch_size)};
    std::string etl_buffer_size_str{human_size(node_settings.etl_buffer_size)};

    // Node settings
    add_node_options(cli, node_settings);

    // Sentry settings
    add_sentry_options(cli, settings.sentry_settings);

    // TODO(canepat) remove when PoS sync works
    cli.add_flag("--sync.force_pow", settings.force_pow, "Force usage of proof-of-work bypassing chain config");

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
    const auto chaindata_page_size{parse_size(chaindata_page_size_str)};
    if (!chaindata_page_size.has_value() || (*chaindata_page_size & (*chaindata_page_size - 1)) != 0) {
        throw std::invalid_argument("--chaindata.pagesize is not a power of 2");
    }
    node_settings.chaindata_env_config.page_size = chaindata_page_size.value();
    const auto mdbx_max_size_hard_limit{chaindata_page_size.value() * sw_db::kMdbxMaxPages};
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

// TODO(canepat) remove by migrating Sentry from ServerContextPool to ClientContextPool
class DummyServerCompletionQueue : public grpc::ServerCompletionQueue {
};

using SentryClientPtr = std::shared_ptr<sentry::api::api_common::SentryClient>;
using SentryServerPtr = std::shared_ptr<sentry::Sentry>;
using SentryPtrPair = std::tuple<SentryClientPtr, SentryServerPtr>;

static SentryPtrPair make_sentry(sentry::Settings sentry_settings, NodeSettings& node_settings,
                                 rpc::ServerContextPool& context_pool, db::ROAccess db_access) {
    SentryServerPtr sentry_server;
    SentryClientPtr sentry_client;

    db::EthStatusDataProvider eth_status_data_provider{db_access, node_settings.chain_config.value()};

    if (node_settings.remote_sentry_addresses.empty()) {
        sentry_settings.data_dir_path = node_settings.data_directory->path();
        // Disable gRPC in the embedded sentry
        sentry_settings.api_address = "";

        // Create embedded server
        sentry_server = std::make_shared<sentry::Sentry>(std::move(sentry_settings), context_pool);

        // Wrap direct client i.e. server in a session client
        sentry_client = std::make_shared<sentry::SessionSentryClient>(
            sentry_server,
            eth_status_data_provider.to_factory_function());
    } else if (node_settings.remote_sentry_addresses.size() == 1) {
        // Create remote client
        auto remote_sentry_client = std::make_shared<sentry::grpc::client::SentryClient>(
            node_settings.remote_sentry_addresses[0],
            *context_pool.next_context().client_grpc_context());
        // Wrap remote client in a session client
        sentry_client = std::make_shared<sentry::SessionSentryClient>(
            remote_sentry_client,
            eth_status_data_provider.to_factory_function());
    } else {
        std::vector<SentryClientPtr> clients;

        for (const auto& address_uri : node_settings.remote_sentry_addresses) {
            // Create remote client
            auto remote_sentry_client = std::make_shared<sentry::grpc::client::SentryClient>(
                address_uri,
                *context_pool.next_context().client_grpc_context());
            // Wrap remote client in a session client
            auto session_sentry_client = std::make_shared<sentry::SessionSentryClient>(
                remote_sentry_client,
                eth_status_data_provider.to_factory_function());
            clients.push_back(session_sentry_client);
        }

        sentry_client = std::make_shared<sentry::MultiSentryClient>(std::move(clients));
    }

    return {sentry_client, sentry_server};
}

// main
int main(int argc, char* argv[]) {
    using namespace boost::placeholders;
    using namespace std::chrono;
    using namespace silkworm::concurrency::awaitable_wait_for_one;
    using namespace silkworm::concurrency::awaitable_wait_for_all;

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
        node_settings.build_info =
            "version=" + std::string(build_info->git_branch) + std::string(build_info->project_version) +
            "build=" + std::string(build_info->system_name) + "-" + std::string(build_info->system_processor) +
            " " + std::string(build_info->build_type) +
            "compiler=" + std::string(build_info->compiler_id) +
            " " + std::string(build_info->compiler_version);
        node_settings.node_name = get_node_name_from_build_info(build_info);

        sw_log::Message(
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
        sw_log::Message("libmdbx",
                        {"version", mdbx_ver.git.describe, "build", mdbx_bld.target, "compiler", mdbx_bld.compiler});

        // Prepare database for takeoff
        cmd::common::run_db_checklist(node_settings);

        auto chaindata_db{db::open_env(node_settings.chaindata_env_config)};

        silkworm::rpc::ServerContextPool context_pool{
            settings.node_settings.server_settings.context_pool_settings,
            [] { return std::make_unique<DummyServerCompletionQueue>(); },
        };

        // Sentry: the peer-2-peer proxy server
        auto [sentry_client, sentry_server] = make_sentry(
            std::move(settings.sentry_settings), settings.node_settings, context_pool, db::ROAccess{chaindata_db});
        auto embedded_sentry_run_if_needed = [&sentry_server = sentry_server]() -> boost::asio::awaitable<void> {
            if (sentry_server) {
                co_await sentry_server->run();
            }
        };

        // Execution: the execution layer engine
        silkworm::node::Node execution_node{settings.node_settings, sentry_client, chaindata_db};
        execution::LocalClient& execution_client{execution_node.execution_local_client()};

        // Set up the execution node (e.g. load pre-verified hashes, download+index snapshots...)
        execution_node.setup();

        // ChainSync: the chain synchronization process based on the consensus protocol
        chainsync::EngineRpcSettings rpc_settings{
            .engine_end_point = settings.rpcdaemon_settings.engine_end_point,
            .private_api_addr = settings.rpcdaemon_settings.private_api_addr,
            .log_verbosity = settings.log_settings.log_verbosity,
            .wait_mode = settings.rpcdaemon_settings.context_pool_settings.wait_mode,
            .jwt_secret_file = settings.rpcdaemon_settings.jwt_secret_file.value(),
        };
        chainsync::Sync chain_sync_process{
            context_pool.next_io_context(),
            chaindata_db,
            execution_client,
            sentry_client,
            *node_settings.chain_config,
            rpc_settings};
        // TODO(canepat) remove when PoS sync works
        if (settings.force_pow) {
            chain_sync_process.force_pow(execution_client);
        }

        auto tasks =
            execution_node.run() &&
            embedded_sentry_run_if_needed() &&
            chain_sync_process.async_run();

        // Trap OS signals
        ShutdownSignal shutdown_signal{context_pool.next_io_context()};

        // Go!
        auto run_future = boost::asio::co_spawn(
            context_pool.next_io_context(),
            std::move(tasks) || shutdown_signal.wait(),
            boost::asio::use_future);
        context_pool.start();
        sw_log::Message() << "Silkworm is now running";

        // Wait for shutdown signal or an exception from tasks
        run_future.get();

        // Graceful exit after user shutdown signal
        sw_log::Message() << "Exiting Silkworm";
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
