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

#include <silkworm/buildinfo.h>
#include <silkworm/lightclient/light_client.hpp>
#include <silkworm/rpc/common/util.hpp>

#include "common.hpp"

using namespace silkworm;
using namespace silkworm::cmd;

cl::Settings parse_cli_settings(int argc, char* argv[]) {
    CLI::App cli{"Silkworm CL LightClient"};

    try {
        cl::Settings settings;
        settings.build_info = silkworm_get_buildinfo();
        add_logging_options(cli, settings.log_settings);
        add_option_num_contexts(cli, settings.num_contexts);
        add_option_wait_mode(cli, settings.wait_mode);
        add_option_chain(cli, settings.chain_id);

        cli.parse(argc, argv);

        return settings;
    } catch (const CLI::ParseError& pe) {
        cli.exit(pe);
        throw;
    }
}

int main(int argc, char* argv[]) {
    try {
        cl::Settings settings = parse_cli_settings(argc, argv);

        log::init(settings.log_settings);
        log::set_thread_name("main");
        // TODO(canepat): this could be an option in Silkworm logging facility
        rpc::Grpc2SilkwormLogGuard log_guard;

        cl::LightClient light_client{std::move(settings)};
        light_client.start();

        const auto pid = boost::this_process::get_id();
        const auto tid = std::this_thread::get_id();
        log::Info() << "[LightClient] LC is now running [pid=" << pid << ", main thread=" << tid << "]";

        light_client.join();

        log::Info() << "[LightClient] LC exiting [pid=" << pid << ", main thread=" << tid << "]";
    } catch (const CLI::ParseError& pe) {
        return -1;
    } catch (const std::exception& e) {
        log::Critical() << "[LightClient] LC exiting due to exception: " << e.what();
        return -2;
    } catch (...) {
        log::Critical() << "[LightClient] LC exiting due to unexpected exception";
        return -3;
    }
}
