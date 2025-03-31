// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
