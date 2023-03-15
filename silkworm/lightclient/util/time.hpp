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

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace silkworm::cl {

constexpr unsigned int kSlotsPerPeriod{8192};

//! Get current Unix time
inline uint64_t current_unix_time() {
    const auto now = std::chrono::system_clock::now();
    const auto unix_time = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    return static_cast<uint64_t>(unix_time);
}

//! Compute the current slot number
inline uint64_t get_current_slot(uint64_t genesis_time, uint64_t seconds_per_slot) {
    const auto current_time = current_unix_time();
    if (current_time < genesis_time) {
        return 0;
    }
    return (current_time - genesis_time) / seconds_per_slot;
}

//! Compute current epoch
inline uint64_t get_current_epoch(uint64_t genesis_time, uint64_t seconds_per_slot, uint64_t slots_per_epoch) {
    return get_current_slot(genesis_time, seconds_per_slot) / slots_per_epoch;
}

//! Convert slot number into period number
inline uint64_t slot_to_period(uint64_t slot) {
    return slot / kSlotsPerPeriod;
}

}  // namespace silkworm::cl
