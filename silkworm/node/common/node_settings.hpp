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

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/db/datastore/etl/collector_settings.hpp>
#include <silkworm/db/datastore/mdbx/mdbx.hpp>
#include <silkworm/db/prune_mode.hpp>
#include <silkworm/infra/common/application_info.hpp>
#include <silkworm/infra/common/directories.hpp>

namespace silkworm {

struct NodeSettings {
    ApplicationInfo build_info;                            // Application build info (human-readable)
    std::unique_ptr<DataDirectory> data_directory;         // Pointer to data folder
    sw_mdbx::EnvConfig chaindata_env_config;               // Chaindata db config
    uint64_t network_id{kMainnetConfig.chain_id};          // Network/Chain id
    std::optional<ChainConfig> chain_config;               // Chain config
    size_t batch_size{512_Mebi};                           // Batch size to use in stages
    size_t etl_buffer_size{256_Mebi};                      // Buffer size for ETL operations
    std::vector<std::string> remote_sentry_addresses;      // Remote Sentry API addresses (host:port,host2:port2,...)
    bool fake_pow{false};                                  // Whether to verify Proof-of-Work (PoW)
    std::optional<evmc::address> etherbase{std::nullopt};  // Coinbase address (PoW only)
    db::PruneMode prune_mode;                              // Prune mode
    uint32_t sync_loop_throttle_seconds{0};                // Minimum interval amongst sync cycle
    uint32_t sync_loop_log_interval_seconds{30};           // Interval for sync loop to emit logs
    bool parallel_fork_tracking_enabled{false};            // Whether to track multiple parallel forks at head
    bool keep_db_txn_open{true};                           // Whether to keep db transaction open between requests
    std::optional<std::string> exec_api_address;           // Execution API GRPC server bind address (IP:port)

    etl::CollectorSettings etl() const {
        return {data_directory->temp().path(), etl_buffer_size};
    }
};

}  // namespace silkworm
