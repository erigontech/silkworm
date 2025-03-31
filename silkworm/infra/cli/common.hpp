// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <optional>
#include <vector>

#include <CLI/CLI.hpp>

#include <silkworm/infra/common/application_info.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/context_pool_settings.hpp>

namespace silkworm::cmd::common {

//! \brief Set up options to populate log settings after cli.parse()
void add_logging_options(CLI::App& cli, log::Settings& log_settings);

//! \brief Set up option for the network to join
void add_option_chain(CLI::App& cli, uint64_t& network_id);

//! \brief Set up option for the data directory path
void add_option_data_dir(CLI::App& cli, std::filesystem::path& data_dir);

//! \brief Set up option for an optional data directory path
void add_option_data_dir(CLI::App& cli, std::optional<std::filesystem::path>& data_dir);

//! \brief Set up option for the node Etherbase address
void add_option_etherbase(CLI::App& cli, std::string& etherbase_address);

//! \brief Set up option for the IP address of Core private gRPC API
void add_option_private_api_address(CLI::App& cli, std::string& private_api_address);

//! \brief Set up option for the remote Sentry gRPC API address(es)
void add_option_remote_sentry_addresses(CLI::App& cli, std::vector<std::string>& addresses, bool is_required);

//! \brief Set up context pool options
void add_context_pool_options(CLI::App& cli, concurrency::ContextPoolSettings& settings);

}  // namespace silkworm::cmd::common
