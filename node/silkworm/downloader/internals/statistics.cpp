/*
   Copyright 2022 The Silkworm Authors

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

#include "statistics.hpp"

#include <iomanip>

namespace silkworm {

std::ostream& operator<<(std::ostream& os, const Download_Statistics& stats) {
    using namespace std::chrono;
    uint64_t perc_received = stats.requested_items > 0 ? stats.received_items * 100 / stats.requested_items : 0;
    uint64_t perc_accepted = stats.received_items > 0 ? stats.accepted_items * 100 / stats.received_items : 0;
    uint64_t perc_rejected = stats.received_items > 0 ? stats.rejected_items() * 100 / stats.received_items : 0;
    uint64_t unknown = stats.rejected_items() - stats.reject_causes.not_requested - stats.reject_causes.duplicated - stats.reject_causes.invalid - stats.reject_causes.bad;

    os << std::setfill('_')
       << "elapsed(m)=" << std::setw(7) << std::right << duration_cast<minutes>(stats.elapsed()).count() << ", "
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

    return os;
}

duration_t Download_Statistics::elapsed() const {
    return std::chrono::system_clock::now() - start_tp;
}

}  // namespace silkworm