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

#pragma once

#include <cstdint>
#include <ostream>
#include <string>

#include "types.hpp"

namespace silkworm {

struct Download_Statistics {
    time_point_t start_tp{std::chrono::system_clock::now()};
    duration_t elapsed() const;

    uint64_t requested_items{0};
    uint64_t received_items{0};
    uint64_t accepted_items{0};
    uint64_t rejected_items() const { return received_items - accepted_items; }

    struct Reject_Causes {
        uint64_t not_requested{0};
        uint64_t duplicated{0};
        uint64_t invalid{0};
        uint64_t bad{0};
    } reject_causes;
};

std::ostream& operator<<(std::ostream& os, const Download_Statistics& stats);

}  // namespace silkworm
