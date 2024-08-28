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

#include "message_expiration.hpp"

namespace silkworm::sentry::discovery::disc_v4 {

std::chrono::time_point<std::chrono::system_clock> make_message_expiration() {
    using namespace std::chrono_literals;
    static const auto kTtl = 20s;
    return std::chrono::system_clock::now() + kTtl;
}

bool is_expired_message_expiration(std::chrono::time_point<std::chrono::system_clock> expiration) {
    return is_time_in_past(expiration);
}

bool is_time_in_past(std::chrono::time_point<std::chrono::system_clock> time) {
    return time < std::chrono::system_clock::now();
}

}  // namespace silkworm::sentry::discovery::disc_v4
