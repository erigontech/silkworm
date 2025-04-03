// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
