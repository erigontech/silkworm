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

#include <string>

#include <CLI/CLI.hpp>
#include <boost/asio/version.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/buildinfo.h>
#include <silkworm/rpc/daemon.hpp>

#include "common/common.hpp"
#include "common/rpcdaemon_options.hpp"

using namespace silkworm;
using namespace silkworm::cmd::common;
using namespace silkworm::rpc;

//! Assemble the application fully-qualified name using the Cable build information
std::string get_name_from_build_info() {
    return get_node_name_from_build_info(silkworm_get_buildinfo());
}

//! Assemble the relevant library version information
std::string get_library_versions() {
    std::string library_versions{"gRPC: "};
    library_versions.append(grpc::Version());
    library_versions.append(" Boost Asio: ");
    library_versions.append(std::to_string(BOOST_ASIO_VERSION));
    return library_versions;
}

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

        return Daemon::run(settings, {get_name_from_build_info(), get_library_versions()});
    } catch (const CLI::ParseError& pe) {
        return cli.exit(pe);
    }
}
