/*
    Copyright 2021-2022 The Silkworm Authors

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
#ifndef SILKWORM_COMMON_SETTINGS_HPP_
#define SILKWORM_COMMON_SETTINGS_HPP_

#include <memory>

#ifdef __APPLE__
// otherwise <boost/asio/detail/socket_types.hpp> dependency doesn't compile
#define _DARWIN_C_SOURCE
#endif
#include <boost/asio/io_context.hpp>

#include <silkworm/chain/config.hpp>
#include <silkworm/common/base.hpp>
#include <silkworm/common/directories.hpp>
#include <silkworm/db/mdbx.hpp>
#include <silkworm/db/prune_mode.hpp>

namespace silkworm {

struct NodeSettings {
    boost::asio::io_context asio_context;            // Async context (e.g. for timers)
    std::unique_ptr<DataDirectory> data_directory;   // Pointer to data folder
    db::EnvConfig chaindata_env_config{};            // Chaindata db config
    uint64_t network_id{kMainnetConfig.chain_id};    // Network/Chain id
    std::optional<ChainConfig> chain_config;         // Chain config
    size_t batch_size{512_Mebi};                     // Batch size to use in stages
    size_t etl_buffer_size{256_Mebi};                // Buffer size for ETL operations
    std::string private_api_addr{"127.0.0.1:9090"};  // Default API listener
    std::string sentry_api_addr{};                   // Default address(es) of sentry
    bool fake_pow{false};                            // Whether to verify Proof-of-Work
    std::unique_ptr<db::PruneMode> prune_mode;       // Prune mode
    uint32_t sync_loop_throttle_seconds{0};          // Minimum interval amongst sync cycle
    uint32_t sync_loop_log_interval_seconds{30};     // Interval for sync loop to emit logs
};

}  // namespace silkworm

#endif  // SILKWORM_COMMON_SETTINGS_HPP_
