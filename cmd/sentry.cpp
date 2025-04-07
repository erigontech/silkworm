// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <memory>

#include <CLI/CLI.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/process/environment.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/infra/cli/common.hpp>
#include <silkworm/infra/cli/shutdown_signal.hpp>
#include <silkworm/infra/common/application_info.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/sentry/cli/sentry_options.hpp>
#include <silkworm/sentry/sentry.hpp>
#include <silkworm/sentry/settings.hpp>

using namespace silkworm;
using namespace silkworm::cmd::common;
using namespace silkworm::sentry;

Settings sentry_parse_cli_settings(int argc, char* argv[]) {
    CLI::App cli{"Sentry - P2P proxy"};

    Settings settings;
    settings.client_id = make_client_id_from_build_info(*silkworm_get_buildinfo());

    add_logging_options(cli, settings.log_settings);
    add_option_data_dir(cli, settings.data_dir_path);
    add_option_chain(cli, settings.network_id);
    add_context_pool_options(cli, settings.context_pool_settings);
    add_sentry_options(cli, settings);

    try {
        cli.parse(argc, argv);
    } catch (const CLI::ParseError& pe) {
        cli.exit(pe);
        throw;
    }

    return settings;
}

void sentry_main(Settings settings) {
    using namespace concurrency::awaitable_wait_for_one;

    log::init(settings.log_settings);
    log::set_thread_name("main");

    silkworm::rpc::ClientContextPool context_pool{
        settings.context_pool_settings,
    };

    Sentry sentry{std::move(settings), context_pool.as_executor_pool()};

    auto run_future = boost::asio::co_spawn(
        context_pool.any_executor(),
        sentry.run() || ShutdownSignal::wait(),
        boost::asio::use_future);

    context_pool.start();

    const auto pid = boost::this_process::get_id();
    const auto tid = std::this_thread::get_id();
    SILK_INFO << "Sentry is now running [pid=" << pid << ", main thread=" << tid << "]";

    // wait until either:
    // - shutdown_signal, then the sentry.run() is cancelled gracefully
    // - sentry.run() exception, then it is rethrown here
    run_future.get();

    context_pool.stop();
    context_pool.join();

    SILK_INFO << "Sentry exiting [pid=" << pid << ", main thread=" << tid << "]";
}

int main(int argc, char* argv[]) {
    try {
        sentry_main(sentry_parse_cli_settings(argc, argv));
    } catch (const CLI::ParseError& pe) {
        return pe.get_exit_code();
    } catch (const std::exception& e) {
        SILK_CRIT << "Sentry exiting due to exception: " << e.what();
        return -2;
    } catch (...) {
        SILK_CRIT << "Sentry exiting due to unexpected exception";
        return -3;
    }
}
