// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <CLI/CLI.hpp>

namespace silkworm::cmd::common {

struct HumanSizeParserValidator : public CLI::Validator {
    HumanSizeParserValidator(size_t min_size, size_t max_size);
};

//! \brief Set up parsing of a human readable bytes size
void add_option_human_size(CLI::App& cli, const std::string& name, size_t& value, size_t min_size, size_t max_size, const std::string& description);

}  // namespace silkworm::cmd::common
