// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "statistics.hpp"

#include <cstdint>
#include <iomanip>

namespace silkworm {

std::ostream& operator<<(std::ostream& os, const DownloadStatistics& stats) {
    using namespace std::chrono;
    uint64_t perc_received = stats.requested_items > 0 ? stats.received_items * 100 / stats.requested_items : 0;
    uint64_t perc_accepted = stats.received_items > 0 ? stats.accepted_items * 100 / stats.received_items : 0;
    uint64_t perc_rejected = stats.received_items > 0 ? stats.rejected_items() * 100 / stats.received_items : 0;
    uint64_t unknown = stats.rejected_items() - stats.reject_causes.not_requested - stats.reject_causes.duplicated -
                       stats.reject_causes.invalid - stats.reject_causes.bad;

    os << std::setfill('_')
       << "req=" << std::setw(7) << std::right << stats.requested_items << ", "
       << "rec=" << std::setw(7) << std::right << stats.received_items << " (" << perc_received << "%) -> "
       << "acc=" << std::setw(7) << std::right << stats.accepted_items << " (" << perc_accepted << "%), "
       << "rej=" << std::setw(7) << std::right << stats.rejected_items() << " (" << perc_rejected << "%";

    os << ", reasons: "
       << "unr=" << stats.reject_causes.not_requested << ", "
       << "dup=" << stats.reject_causes.duplicated << ", "
       << "inv=" << stats.reject_causes.invalid << ", "
       << "bad=" << stats.reject_causes.bad << ", "
       << "unk=" << unknown << ")";

    os << " [elapsed(m)=" << duration_cast<minutes>(stats.elapsed()).count() << "]";

    return os;
}

duration_t DownloadStatistics::elapsed() const {
    return std::chrono::system_clock::now() - start_tp;
}

void NetworkStatistics::inaccurate_reset() {
    // during this execution members can be updated making results inaccurate, but we do not need precision here
    received_msgs = 0;
    received_bytes = 0;
    nonsolic_msgs = 0;
    internal_msgs = 0;
    tried_msgs = 0;
    sent_msgs = 0;
    processed_msgs = 0;
    nack_msgs = 0;
    malformed_msgs = 0;
}

void NetworkStatistics::inaccurate_copy(const NetworkStatistics& other) {
    // during this execution members can be updated making results inaccurate, but we do not need precision here
    received_msgs = other.received_msgs.load();
    received_bytes = other.received_bytes.load();
    nonsolic_msgs = other.nonsolic_msgs.load();
    internal_msgs = other.internal_msgs.load();
    tried_msgs = other.tried_msgs.load();
    sent_msgs = other.sent_msgs.load();
    processed_msgs = other.processed_msgs.load();
    nack_msgs = other.nack_msgs.load();
    malformed_msgs = other.malformed_msgs.load();
}

#define SHOW(LABEL, VARIABLE, FACTOR)                                                       \
    (os << std::setfill('_') << std::right                                                  \
        << ", " LABEL ":" << std::setw(5) << curr.VARIABLE.load() / (FACTOR)                \
        << "(+" << std::setw(2) << (curr.VARIABLE.load() - prev.VARIABLE.load()) / (FACTOR) \
        << ", +" << std::setw(2) << (curr.VARIABLE.load() - prev.VARIABLE.load()) / (FACTOR) / elapsed_s << "/s)")

std::ostream& operator<<(std::ostream& os, std::tuple<NetworkStatistics&, NetworkStatistics&, seconds_t> stats) {
    NetworkStatistics& prev = get<0>(stats);
    NetworkStatistics& curr = get<1>(stats);
    seconds_t elapsed = get<2>(stats);
    auto elapsed_s = static_cast<uint64_t>(elapsed.count());

    os << std::setfill('_') << std::right;

    SHOW("received", received_msgs, 1);
    SHOW("recv-kb", received_bytes, 1000);
    SHOW("processed", processed_msgs, 1);
    SHOW("tried", tried_msgs, 1);
    SHOW("sent", sent_msgs, 1);
    SHOW("nack", nack_msgs, 1);
    SHOW("nonsolic", nonsolic_msgs, 1);
    SHOW("internal", internal_msgs, 1);
    SHOW("malformed", malformed_msgs, 1);

    os << " [last_update=" << elapsed.count() << "s]";

    return os;
}

}  // namespace silkworm