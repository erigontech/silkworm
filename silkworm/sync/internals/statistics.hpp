// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>
#include <cstdint>
#include <ostream>
#include <string>

#include "types.hpp"

namespace silkworm {

struct DownloadStatistics {
    time_point_t start_tp{std::chrono::system_clock::now()};
    duration_t elapsed() const;

    uint64_t requested_items{0};
    uint64_t received_items{0};
    uint64_t accepted_items{0};
    uint64_t rejected_items() const { return received_items - accepted_items; }

    struct RejectCauses {
        uint64_t not_requested{0};
        uint64_t duplicated{0};
        uint64_t invalid{0};
        uint64_t bad{0};
    } reject_causes;

    std::string to_string() const;
};

std::ostream& operator<<(std::ostream& os, const DownloadStatistics& stats);

struct NetworkStatistics {
    std::atomic<uint64_t> received_msgs{0};
    std::atomic<uint64_t> received_bytes{0};
    std::atomic<uint64_t> nonsolic_msgs{0};
    std::atomic<uint64_t> internal_msgs{0};
    std::atomic<uint64_t> tried_msgs{0};
    std::atomic<uint64_t> sent_msgs{0};
    std::atomic<uint64_t> processed_msgs{0};
    std::atomic<uint64_t> nack_msgs{0};
    std::atomic<uint64_t> malformed_msgs{0};

    void inaccurate_reset();
    void inaccurate_copy(const NetworkStatistics&);
};

using IntervalNetworkStatistics = std::tuple<NetworkStatistics&, NetworkStatistics&, seconds_t>;

std::ostream& operator<<(std::ostream& os, const IntervalNetworkStatistics& stats);

}  // namespace silkworm
