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

#include <filesystem>

#include <CLI/CLI.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/rpc/server/wait_strategy.hpp>
#include <silkworm/node/snapshot/settings.hpp>

namespace silkworm::cmd::common {

//! Assemble the full node name using the Cable build information
std::string get_node_name_from_build_info(const buildinfo* build_info);

struct PruneModeValidator : public CLI::Validator {
    explicit PruneModeValidator();
};

//! \brief Set up options to populate log settings after cli.parse()
void add_logging_options(CLI::App& cli, log::Settings& log_settings);

//! \brief Set up option for the network to join
void add_option_chain(CLI::App& cli, uint64_t& network_id);

//! \brief Set up option for the data directory path
void add_option_data_dir(CLI::App& cli, std::filesystem::path& data_dir);

//! \brief Set up option for the node Etherbase address
void add_option_etherbase(CLI::App& cli, std::string& etherbase_address);

//! \brief Set up option for maximum number of database readers
void add_option_db_max_readers(CLI::App& cli, uint32_t& max_readers);

//! \brief Set up option for the IP address of Core private gRPC API
void add_option_private_api_address(CLI::App& cli, std::string& private_api_address);

//! \brief Set up option for the IP address of Sentry gRPC API
void add_option_sentry_api_address(CLI::App& cli, std::string& sentry_api_address);

//! \brief Set up option for the IP address(es) of external Sentry component(s)
void add_option_external_sentry_address(CLI::App& cli, std::string& external_sentry_address);

//! \brief Set up parsing of the number of RPC execution contexts (i.e. threading model)
void add_option_num_contexts(CLI::App& cli, uint32_t& num_contexts);

//! \brief Set up parsing of the wait mode (e.g. block, sleep, spin...) in RPC execution contexts
void add_option_wait_mode(CLI::App& cli, silkworm::rpc::WaitMode& wait_mode);

//! \brief Setup options to populate snapshot settings after cli.parse()
void add_snapshot_options(CLI::App& cli, SnapshotSettings& snapshot_settings);

}  // namespace silkworm::cmd::common
