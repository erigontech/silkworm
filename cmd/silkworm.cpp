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
#include <silkworm/db/cli/snapshot_options.hpp>
#include <silkworm/infra/cli/common.hpp>
#include <silkworm/infra/cli/shutdown_signal.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/node/cli/node_options.hpp>
#include <silkworm/node/node.hpp>
#include <silkworm/rpc/cli/rpcdaemon_options.hpp>
#include <silkworm/sentry/cli/sentry_options.hpp>

using namespace silkworm;

using silkworm::BlockNum;
using silkworm::DataDirectory;
using silkworm::human_size;
using silkworm::cmd::common::ShutdownSignal;

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

void add_rpc_server_settings(CLI::App& cli, rpc::ServerSettings& server_settings) {
    using namespace silkworm::cmd::common;
    add_option_private_api_address(cli, server_settings.address_uri);
    add_context_pool_options(cli, server_settings.context_pool_settings);
}

void parse_silkworm_command_line(CLI::App& cli, int argc, char* argv[], node::Settings& settings) {
    using namespace silkworm::cmd;
    using namespace silkworm::cmd::common;

    std::filesystem::path data_dir_path;
    add_option_data_dir(cli, data_dir_path);

    // Node settings
    add_node_options(cli, settings.node_settings);

    // Sentry settings
    add_sentry_options(cli, settings.sentry_settings);

    add_rpc_server_settings(cli, settings.server_settings);

    // Snapshot&Bittorrent options
    add_snapshot_options(cli, settings.snapshot_settings);

    // Prune options
    std::string prune_mode;
    auto& prune_opts = *cli.add_option_group("Prune", "Prune options to delete ancient data from DB");
    prune_opts
        .add_option("--prune", prune_mode,
                    "Delete data older than 90K blocks (see \"--prune.*.older\" to set a different block number)\n"
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

    // node::NodeSettings
    auto& node_settings = settings.node_settings;

    const auto build_info = silkworm_get_buildinfo();
    node_settings.build_info = make_application_info(build_info);

    const size_t chaindata_page_size = node_settings.chaindata_env_config.page_size;
    if ((chaindata_page_size & (chaindata_page_size - 1)) != 0) {
        throw std::invalid_argument("--chaindata.pagesize is not a power of 2");
    }

    const size_t mdbx_max_size_hard_limit = chaindata_page_size * datastore::kvdb::kMdbxMaxPages;
    if (node_settings.chaindata_env_config.max_size > mdbx_max_size_hard_limit) {
        throw std::invalid_argument("--chaindata.maxsize exceeds max allowed size by page size i.e" +
                                    human_size(mdbx_max_size_hard_limit));
    }

    if (node_settings.chaindata_env_config.growth_size > (mdbx_max_size_hard_limit / /* two increments ?*/ 2u)) {
        throw std::invalid_argument("--chaindata.growthsize must be <=" + human_size(mdbx_max_size_hard_limit / 2));
    }

    node_settings.data_directory = std::make_unique<DataDirectory>(data_dir_path, /*create=*/true);
    node_settings.chaindata_env_config.path = node_settings.data_directory->chaindata().path().string();

    // Parse prune mode
    db::PruneDistance older_history, older_receipts, older_senders, older_tx_index, older_call_traces;
    if (cli["--prune.h.older"]->count()) older_history.emplace(cli["--prune.h.older"]->as<BlockNum>());
    if (cli["--prune.r.older"]->count()) older_receipts.emplace(cli["--prune.r.older"]->as<BlockNum>());
    if (cli["--prune.s.older"]->count()) older_senders.emplace(cli["--prune.s.older"]->as<BlockNum>());
    if (cli["--prune.t.older"]->count()) older_tx_index.emplace(cli["--prune.t.older"]->as<BlockNum>());
    if (cli["--prune.c.older"]->count()) older_call_traces.emplace(cli["--prune.c.older"]->as<BlockNum>());

    db::PruneThreshold before_history, before_receipts, before_senders, before_tx_index, before_call_traces;
    if (cli["--prune.h.before"]->count()) before_history.emplace(cli["--prune.h.before"]->as<BlockNum>());
    if (cli["--prune.r.before"]->count()) before_receipts.emplace(cli["--prune.r.before"]->as<BlockNum>());
    if (cli["--prune.s.before"]->count()) before_senders.emplace(cli["--prune.s.before"]->as<BlockNum>());
    if (cli["--prune.t.before"]->count()) before_tx_index.emplace(cli["--prune.t.before"]->as<BlockNum>());
    if (cli["--prune.c.before"]->count()) before_call_traces.emplace(cli["--prune.c.before"]->as<BlockNum>());

    node_settings.prune_mode = db::parse_prune_mode(
        prune_mode,
        older_history, older_receipts, older_senders, older_tx_index, older_call_traces,
        before_history, before_receipts, before_senders, before_tx_index, before_call_traces);

    // snapshots::SnapshotSettings
    auto& snapshot_settings = settings.snapshot_settings;
    snapshot_settings.repository_path = node_settings.data_directory->snapshots().path();
    snapshot_settings.bittorrent_settings.repository_path = snapshot_settings.repository_path;

    // sentry::Settings
    settings.sentry_settings.client_id = node_settings.build_info.client_id;
    settings.sentry_settings.data_dir_path = node_settings.data_directory->path();
    settings.sentry_settings.network_id = node_settings.network_id;
}

// main
int main(int argc, char* argv[]) {
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
        node::Settings settings;
        parse_silkworm_command_line(cli, argc, argv, settings);

        // Initialize logging with cli settings
        log::init(settings.log_settings);
        log::set_thread_name("main-thread");

        log::Info("Silkworm", build_info_as_log_args(silkworm_get_buildinfo()));

        silkworm::rpc::ClientContextPool context_pool{
            settings.server_settings.context_pool_settings,
        };

        silkworm::node::Node execution_node{
            context_pool,
            settings,
        };

        // Go!
        auto run_future = boost::asio::co_spawn(
            context_pool.any_executor(),
            execution_node.run() || ShutdownSignal::wait(),
            boost::asio::use_future);
        context_pool.start();
        SILK_INFO << "Silkworm is now running";

        // Wait for shutdown signal or an exception from tasks
        run_future.get();

        // Graceful exit after user shutdown signal
        SILK_INFO << "Exiting Silkworm";
        return 0;
    } catch (const CLI::ParseError& ex) {
        // Let CLI11 handle any error occurred parsing command-line args
        return cli.exit(ex);
    } catch (const std::exception& ex) {
        // Any exception during run leads to termination
        SILK_CRIT << "Unrecoverable failure: " << ex.what();
        return -1;
    } catch (...) {
        // Any unknown exception during run leads to termination
        SILK_CRIT << "Unrecoverable failure: unexpected exception";
        return -2;
    }
}
