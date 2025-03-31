// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "human_size_option.hpp"

#include <silkworm/core/common/util.hpp>

namespace silkworm::cmd::common {

HumanSizeParserValidator::HumanSizeParserValidator(size_t min_size, size_t max_size) {
    std::string range_desc = "range [" + human_size(min_size) + " - " + human_size(max_size) + "]";
    description(range_desc);

    func_ = [=](const std::string& value) -> std::string {
        auto parsed_size = parse_size(value);
        if (!parsed_size) {
            return std::string("Value " + value + " is not a parseable size");
        }
        if ((parsed_size.value() < min_size) || (parsed_size.value() > max_size)) {
            return "Value " + value + " not in " + range_desc;
        }
        return {};
    };
}

void add_option_human_size(CLI::App& cli, const std::string& name, size_t& value, size_t min_size, size_t max_size, const std::string& description) {
    CLI::Option* option = cli.add_option(name, [&value](const CLI::results_t& results) -> bool {
        auto value_opt = parse_size(results[0]);
        if (value_opt) {
            value = *value_opt;
        }
        return value_opt.has_value();
    });
    option->description(description);
    option->default_str(human_size(value));
    option->check(HumanSizeParserValidator{min_size, max_size});
}

}  // namespace silkworm::cmd::common
