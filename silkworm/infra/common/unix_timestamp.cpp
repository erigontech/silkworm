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

#include "unix_timestamp.hpp"

namespace silkworm {

uint64_t unix_timestamp_from_time_point(std::chrono::time_point<std::chrono::system_clock> time_point) {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(time_point.time_since_epoch()).count());
}

std::chrono::time_point<std::chrono::system_clock> time_point_from_unix_timestamp(uint64_t timestamp) {
    return std::chrono::time_point<std::chrono::system_clock>{std::chrono::seconds(timestamp)};
}

}  // namespace silkworm
