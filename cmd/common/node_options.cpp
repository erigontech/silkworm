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

#include "node_options.hpp"

#include <filesystem>
#include <string>

#include <silkworm/core/common/util.hpp>

#include "common.hpp"
#include "human_size_option.hpp"

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

    // Chain options
    add_option_chain(cli, settings.network_id);
}

}  // namespace silkworm::cmd::common
