// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <CLI/CLI.hpp>

namespace silkworm::cmd::common {

struct IPEndpointValidator : public CLI::Validator {
    explicit IPEndpointValidator(bool allow_empty = false);
};

//! \brief Set up parsing of the specified IP:port endpoint
void add_option_ip_endpoint(CLI::App& cli, const std::string& name, std::string& address, const std::string& description);

}  // namespace silkworm::cmd::common
