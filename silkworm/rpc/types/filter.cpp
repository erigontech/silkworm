// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "filter.hpp"

#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/rpc/common/util.hpp>

std::ostream& operator<<(std::ostream& out, const std::optional<silkworm::rpc::FilterAddresses>& addresses) {
    if (addresses.has_value()) {
        const auto& address_vector = addresses.value();
        out << "[";
        for (size_t i{0}; i < address_vector.size(); ++i) {
            out << address_vector[i];
            if (i != address_vector.size() - 1) {
                out << " ";
            }
        }
        out << "]";
    } else {
        out << "null";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const silkworm::rpc::FilterSubTopics& subtopics) {
    out << "[";
    for (size_t i{0}; i < subtopics.size(); ++i) {
        out << silkworm::to_hex(subtopics[i], true);
        if (i != subtopics.size() - 1) {
            out << " ";
        }
    }
    out << "]";
    return out;
}

std::ostream& operator<<(std::ostream& out, const std::optional<silkworm::rpc::FilterTopics>& topics) {
    if (topics.has_value()) {
        const auto& topic_vector = topics.value();
        out << "[";
        for (size_t i{0}; i < topic_vector.size(); ++i) {
            out << topic_vector[i];
            if (i != topic_vector.size() - 1) {
                out << " ";
            }
        }
        out << "]";
    } else {
        out << "null";
    }
    return out;
}

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const Filter& filter) {
    out << "from_block: " << filter.from_block.value_or("null");
    out << ", to_block: " << filter.to_block.value_or("null");
    out << ", addresses: " << filter.addresses;
    out << ", topics: " << filter.topics;
    out << ", block_hash: " << filter.block_hash.value_or("null");
    return out;
}

std::ostream& operator<<(std::ostream& out, const LogFilterOptions& filter_options) {
    out << "add_timestamp: " << std::boolalpha << filter_options.add_timestamp;
    out << ", logCount: " << filter_options.log_count;
    out << ", blockCount: " << filter_options.block_count;
    out << ", ignore_topics_order: " << std::boolalpha << filter_options.ignore_topics_order;
    return out;
}

}  // namespace silkworm::rpc
