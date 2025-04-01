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

#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <evmc/evmc.hpp>

namespace silkworm::rpc {

using FilterAddresses = std::vector<evmc::address>;
using FilterSubTopics = std::vector<evmc::bytes32>;
using FilterTopics = std::vector<FilterSubTopics>;

struct Filter {
    std::optional<std::string> from_block;
    std::optional<std::string> to_block;
    FilterAddresses addresses;
    FilterTopics topics;
    std::optional<std::string> block_hash;

    std::string to_string() const;
};

struct LogFilterOptions {
    bool add_timestamp{false};
    bool overwrite_log_index{false};
    std::uint64_t log_count{0};
    std::uint64_t block_count{0};
    bool ignore_topics_order{false};

    std::string to_string() const;
};

std::ostream& operator<<(std::ostream& out, const Filter& filter);
std::ostream& operator<<(std::ostream& out, const LogFilterOptions& filter_options);

}  // namespace silkworm::rpc

std::ostream& operator<<(std::ostream& out, const std::optional<silkworm::rpc::FilterAddresses>& addresses);
std::ostream& operator<<(std::ostream& out, const silkworm::rpc::FilterSubTopics& subtopics);
std::ostream& operator<<(std::ostream& out, const std::optional<silkworm::rpc::FilterTopics>& topics);
