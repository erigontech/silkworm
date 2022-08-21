/*
    Copyright 2021 The Silkworm Authors

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

#include <silkworm/common/log.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/rpc/server/wait_strategy.hpp>

namespace silkworm::cmd {

//! \brief Parses command line arguments for silkworm executable
//! \remark This implements the set of CLI args for silkworm executable ONLY !
void parse_silkworm_command_line(CLI::App& cli, int argc, char* argv[], log::Settings& log_settings,
                                 NodeSettings& node_settings);

//! \brief Ensures database is ready for take off and consistent with command line arguments
void run_preflight_checklist(NodeSettings& node_settings);

struct IPEndPointValidator : public CLI::Validator {
    explicit IPEndPointValidator(bool allow_empty = false);
};

//! \brief Sets up logging options to populate log_settings after cli.parse()
void add_logging_options(CLI::App& cli, log::Settings& log_settings);

//! \brief Sets up parsing of the DataDirectory path
void add_option_data_dir(CLI::App& cli, std::filesystem::path& data_dir);

//! \brief Sets up parsing of num_contexts
void add_option_num_contexts(CLI::App& cli, uint32_t& num_contexts);

//! \brief Sets up parsing of wait_mode
void add_option_wait_mode(CLI::App& cli, silkworm::rpc::WaitMode& wait_mode);

}  // namespace silkworm::cmd
