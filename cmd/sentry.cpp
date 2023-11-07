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

#include <CLI/CLI.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/process/environment.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/buildinfo.h>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/sentry/sentry.hpp>
#include <silkworm/sentry/settings.hpp>

#include "common/common.hpp"
#include "common/sentry_options.hpp"
#include "common/shutdown_signal.hpp"

using namespace silkworm;
using namespace silkworm::cmd::common;
using namespace silkworm::sentry;

Settings sentry_parse_cli_settings(int argc, char* argv[]) {
    CLI::App cli{"Sentry - P2P proxy"};

    Settings settings;
    settings.client_id = Sentry::make_client_id(*silkworm_get_buildinfo());

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

    ShutdownSignal shutdown_signal{context_pool.any_executor()};

    Sentry sentry{std::move(settings), context_pool.as_executor_pool()};

    auto run_future = boost::asio::co_spawn(
        context_pool.any_executor(),
        sentry.run() || shutdown_signal.wait(),
        boost::asio::use_future);

    context_pool.start();

    const auto pid = boost::this_process::get_id();
    const auto tid = std::this_thread::get_id();
    log::Info() << "Sentry is now running [pid=" << pid << ", main thread=" << tid << "]";

    // wait until either:
    // - shutdown_signal, then the sentry.run() is cancelled gracefully
    // - sentry.run() exception, then it is rethrown here
    run_future.get();

    context_pool.stop();
    context_pool.join();

    log::Info() << "Sentry exiting [pid=" << pid << ", main thread=" << tid << "]";
}

int main(int argc, char* argv[]) {
    try {
        sentry_main(sentry_parse_cli_settings(argc, argv));
    } catch (const CLI::ParseError& pe) {
        return -1;
    } catch (const std::exception& e) {
        log::Critical() << "Sentry exiting due to exception: " << e.what();
        return -2;
    } catch (...) {
        log::Critical() << "Sentry exiting due to unexpected exception";
        return -3;
    }
}
