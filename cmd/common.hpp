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
#include <silkworm/common/log.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/rpc/server/server_config.hpp>
#include <silkworm/rpc/server/wait_strategy.hpp>

namespace silkworm::cmd {

//! The overall settings for Silkworm Core component
struct SilkwormCoreSettings {
    silkworm::log::Settings log_settings;
    silkworm::NodeSettings node_settings;
    silkworm::rpc::ServerConfig server_settings;
};

//! \brief Parses command line arguments for Silkworm executables
void parse_silkworm_command_line(CLI::App& cli, int argc, char* argv[], SilkwormCoreSettings& settings);

//! \brief Ensure database is ready to take off and consistent with command line arguments
void run_preflight_checklist(NodeSettings& node_settings, bool init_if_empty = true);

//! Assemble the full node name using the Cable build information
std::string get_node_name_from_build_info(const buildinfo* build_info);

struct HumanSizeParserValidator : public CLI::Validator {
    template <typename T>
    explicit HumanSizeParserValidator(T min, std::optional<T> max = std::nullopt) {
        std::stringstream out;
        out << " in [" << min << " - " << (max.has_value() ? max.value() : "inf") << "]";
        description(out.str());

        func_ = [min, max](const std::string& value) -> std::string {
            auto parsed_size{parse_size(value)};
            if (!parsed_size.has_value()) {
                return std::string("Value " + value + " is not a parseable size");
            }
            auto min_size{parse_size(min).value()};
            auto max_size{max.has_value() ? parse_size(max.value()).value() : UINT64_MAX};
            if (parsed_size.value() < min_size || parsed_size.value() > max_size) {
                return "Value " + value + " not in range " + min + " to " + (max.has_value() ? max.value() : "∞");
            }
            return {};
        };
    }
};

struct IPEndPointValidator : public CLI::Validator {
    explicit IPEndPointValidator(bool allow_empty = false);
};

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

//! \brief Set up parsing of the specified IP address
void add_option_ip_address(CLI::App& cli, const std::string& name, std::string& address, const std::string& description);

//! \brief Set up parsing of the number of RPC execution contexts (i.e. threading model)
void add_option_num_contexts(CLI::App& cli, uint32_t& num_contexts);

//! \brief Set up parsing of the wait mode (e.g. block, sleep, spin...) in RPC execution contexts
void add_option_wait_mode(CLI::App& cli, silkworm::rpc::WaitMode& wait_mode);

}  // namespace silkworm::cmd
