/*
   Copyright 2023 The Silkworm Authors

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

#include <CLI/CLI.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/infra/cli/common.hpp>
#include <silkworm/rpc/cli/rpcdaemon_options.hpp>
#include <silkworm/rpc/daemon.hpp>

using namespace silkworm;
using namespace silkworm::cmd::common;
using namespace silkworm::rpc;

int main(int argc, char* argv[]) {
    CLI::App cli{"Silkrpc - C++ implementation of Ethereum JSON RPC API service"};

    DaemonSettings settings;

    try {
        // Parse and validate program arguments
        add_logging_options(cli, settings.log_settings);
        add_option_data_dir(cli, settings.datadir);
        add_context_pool_options(cli, settings.context_pool_settings);
        add_rpcdaemon_options(cli, settings);
        cli.parse(argc, argv);

        // Extract versioning information from Cable build information
        settings.build_info = make_application_info(silkworm_get_buildinfo());

        return Daemon::run(settings);
    } catch (const CLI::ParseError& pe) {
        return cli.exit(pe);
    }
}
