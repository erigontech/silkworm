// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "node_options.hpp"

#include <filesystem>
#include <string>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/cli/common.hpp>
#include <silkworm/infra/cli/human_size_option.hpp>

namespace silkworm::cmd::common {

void add_node_options(CLI::App& cli, NodeSettings& settings) {
    cli.add_flag("--chaindata.exclusive", settings.chaindata_env_config.exclusive,
                 "Chaindata database opened in exclusive mode");
    cli.add_flag("--chaindata.readahead", settings.chaindata_env_config.read_ahead,
                 "Chaindata database enable readahead");
    cli.add_flag("--chaindata.writemap", settings.chaindata_env_config.write_map,
                 "Chaindata database enable writemap");

    add_option_human_size(
        cli, "--chaindata.growthsize", settings.chaindata_env_config.growth_size,
        32_Mebi, 128_Tebi,
        "Chaindata database growth size.");
    add_option_human_size(
        cli, "--chaindata.pagesize", settings.chaindata_env_config.page_size,
        256, 64_Kibi,
        "Chaindata database page size. A power of 2");
    add_option_human_size(
        cli, "--chaindata.maxsize", settings.chaindata_env_config.max_size,
        32_Mebi, 128_Tebi,
        "Chaindata database max size.");

    add_option_human_size(
        cli, "--batchsize", settings.batch_size,
        64_Mebi, 16_Gibi,
        "Batch size for stage execution");
    add_option_human_size(
        cli, "--etl.buffersize", settings.etl_buffer_size,
        64_Mebi, 1_Gibi,
        "Buffer size for ETL operations");

    cli.add_option("--sync.loop.throttle", settings.sync_loop_throttle_seconds,
                   "Sets the minimum delay between sync loop starts (in seconds)")
        ->capture_default_str()
        ->check(CLI::Range(1u, 7200u));

    cli.add_option("--sync.loop.log.interval", settings.sync_loop_log_interval_seconds,
                   "Sets the interval between sync loop logs (in seconds)")
        ->capture_default_str()
        ->check(CLI::Range(10u, 600u));

    cli.add_flag("--fakepow", settings.fake_pow, "Disables proof-of-work verification");

    add_option_remote_sentry_addresses(cli, settings.remote_sentry_addresses, /*is_required=*/false);

    cli.add_option("--exec.api.addr", settings.exec_api_address)
        ->description("Execution API GRPC server bind address (IP:port) for connecting an external chain sync client");

    // Chain options
    add_option_chain(cli, settings.network_id);
}

}  // namespace silkworm::cmd::common
