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

#include <optional>
#include <sstream>
#include <string>

#include <CLI/CLI.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::cmd::common {

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

}  // namespace silkworm::cmd::common
