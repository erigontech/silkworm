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

#pragma once

#include <CLI/CLI.hpp>

namespace silkworm::cmd::common {

struct IPEndpointValidator : public CLI::Validator {
    explicit IPEndpointValidator(bool allow_empty = false);
};

//! \brief Set up parsing of the specified IP:port endpoint
void add_option_ip_endpoint(CLI::App& cli, const std::string& name, std::string& address, const std::string& description);

}  // namespace silkworm::cmd::common
