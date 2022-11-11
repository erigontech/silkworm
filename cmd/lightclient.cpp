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

#include <CLI/CLI.hpp>
#include <boost/process/environment.hpp>

#include <silkworm/rpc/util.hpp>

#include "common.hpp"

using namespace silkworm;
using namespace silkworm::cmd;

void lightclient_main(/*Settings settings*/) {
    log::Settings log_settings{};
    log::init(log_settings /*settings.log_settings*/);
    log::set_thread_name("main");
    // TODO(canepat): this could be an option in Silkworm logging facility
    silkworm::rpc::Grpc2SilkwormLogGuard log_guard;

    // Sentry sentry{std::move(settings)};
    // sentry.start();

    const auto pid = boost::this_process::get_id();
    const auto tid = std::this_thread::get_id();
    log::Info() << "LightClient is now running [pid=" << pid << ", main thread=" << tid << "]";
    // sentry.join();

    log::Info() << "LightClient exiting [pid=" << pid << ", main thread=" << tid << "]";
}

int main(int /*argc*/, char* /*argv*/[]) {
    try {
        lightclient_main(/*sentry_parse_cli_settings(argc, argv)*/);
    } catch (const CLI::ParseError& pe) {
        return -1;
    } catch (const std::exception& e) {
        log::Critical() << "LightClient exiting due to exception: " << e.what();
        return -2;
    } catch (...) {
        log::Critical() << "LightClient exiting due to unexpected exception";
        return -3;
    }
}
