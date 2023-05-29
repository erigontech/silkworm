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
#include "human_size_parser_validator.hpp"
#include "snapshot_options.hpp"

namespace silkworm::cmd::common {

void add_node_options(CLI::App& cli, node::Settings& settings) {
    std::string chaindata_max_size_str{human_size(settings.chaindata_env_config.max_size)};
    std::string chaindata_growth_size_str{human_size(settings.chaindata_env_config.growth_size)};
    std::string chaindata_page_size_str{human_size(settings.chaindata_env_config.page_size)};
    std::string batch_size_str{human_size(settings.batch_size)};
    std::string etl_buffer_size_str{human_size(settings.etl_buffer_size)};

    cli.add_flag("--chaindata.exclusive", settings.chaindata_env_config.exclusive,
                 "Chaindata database opened in exclusive mode");
    cli.add_flag("--chaindata.readahead", settings.chaindata_env_config.read_ahead,
                 "Chaindata database enable readahead");
    cli.add_flag("--chaindata.writemap", settings.chaindata_env_config.write_map,
                 "Chaindata database enable writemap");

    cli.add_option("--chaindata.growthsize", chaindata_growth_size_str, "Chaindata database growth size.")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("64MB"));
    cli.add_option("--chaindata.pagesize", chaindata_page_size_str, "Chaindata database page size. A power of 2")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("256B", {"65KB"}));
    cli.add_option("--chaindata.maxsize", chaindata_max_size_str, "Chaindata database max size.")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("32MB", {"128TB"}));

    cli.add_option("--batchsize", batch_size_str, "Batch size for stage execution")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("64MB", {"16GB"}));
    cli.add_option("--etl.buffersize", etl_buffer_size_str, "Buffer size for ETL operations")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("64MB", {"1GB"}));

    cli.add_option("--sync.loop.throttle", settings.sync_loop_throttle_seconds,
                   "Sets the minimum delay between sync loop starts (in seconds)")
        ->capture_default_str()
        ->check(CLI::Range(1u, 7200u));

    cli.add_option("--sync.loop.log.interval", settings.sync_loop_log_interval_seconds,
                   "Sets the interval between sync loop logs (in seconds)")
        ->capture_default_str()
        ->check(CLI::Range(10u, 600u));

    cli.add_flag("--fakepow", settings.fake_pow, "Disables proof-of-work verification");

    add_option_private_api_address(cli, settings.server_settings.address_uri);
    add_option_remote_sentry_addresses(cli, settings.remote_sentry_addresses, /*is_required=*/false);

    // Chain options
    add_option_chain(cli, settings.network_id);

    // RPC server options
    add_context_pool_options(cli, settings.server_settings.context_pool_settings);

    // Snapshot&Bittorrent options
    add_snapshot_options(cli, settings.snapshot_settings);
}

}  // namespace silkworm::cmd::common
