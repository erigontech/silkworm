// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "filter.hpp"

#include <silkworm/core/common/util.hpp>

#include "types.hpp"

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const Filter& filter) {
    if (filter.from_block != std::nullopt) {
        json["fromBlock"] = filter.from_block.value();
    }
    if (filter.to_block != std::nullopt) {
        json["toBlock"] = filter.to_block.value();
    }
    if (!filter.addresses.empty()) {
        if (filter.addresses.size() == 1) {
            json["address"] = filter.addresses[0];
        } else {
            json["address"] = filter.addresses;
        }
    }
    if (!filter.topics.empty()) {
        json["topics"] = filter.topics;
    }
    if (filter.block_hash != std::nullopt) {
        json["blockHash"] = filter.block_hash.value();
    }
}

void from_json(const nlohmann::json& json, Filter& filter) {
    if (json.count("fromBlock") != 0) {
        const auto& json_from_block = json.at("fromBlock");
        if (json_from_block.is_string()) {
            filter.from_block = json_from_block.get<std::string>();
        } else {
            filter.from_block = to_quantity(json_from_block.get<BlockNum>());
        }
    }
    if (json.count("toBlock") != 0) {
        const auto& json_to_block = json.at("toBlock");
        if (json_to_block.is_string()) {
            filter.to_block = json_to_block.get<std::string>();
        } else {
            filter.to_block = to_quantity(json_to_block.get<BlockNum>());
        }
    }
    if (json.count("address") != 0) {
        if (json.at("address").is_string()) {
            filter.addresses = {json.at("address").get<evmc::address>()};
        } else {
            filter.addresses = json.at("address").get<FilterAddresses>();
        }
    }
    if (json.count("topics") != 0) {
        auto topics = json.at("topics");
        if (topics != nlohmann::detail::value_t::null) {
            for (auto& topic_item : topics) {
                if (topic_item.is_null()) {
                    topic_item = FilterSubTopics{};
                }
                if (topic_item.is_string()) {
                    topic_item = FilterSubTopics{topic_item};
                }
            }
            filter.topics = topics.get<FilterTopics>();
        }
    }
    if (json.count("blockHash") != 0) {
        filter.block_hash = json.at("blockHash").get<std::string>();
    }
}

void from_json(const nlohmann::json& json, LogFilterOptions& filter_options) {
    if (json.count("logCount") != 0) {
        const auto& value = json.at("logCount");
        filter_options.log_count = value.get<std::uint64_t>();
    }
    if (json.count("blockCount") != 0) {
        const auto& value = json.at("blockCount");
        filter_options.block_count = value.get<std::uint64_t>();
    }
    if (json.count("ignoreTopicsOrder") != 0) {
        const auto& value = json.at("ignoreTopicsOrder");
        filter_options.ignore_topics_order = value.get<bool>();
    }
}
}  // namespace silkworm::rpc
