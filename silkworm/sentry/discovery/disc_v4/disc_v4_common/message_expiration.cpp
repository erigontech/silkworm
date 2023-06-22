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

namespace silkworm::sentry::discovery::disc_v4::disc_v4_common {

std::chrono::time_point<std::chrono::system_clock> make_message_expiration() {
    using namespace std::chrono_literals;
    static const auto ttl = 20s;
    return std::chrono::system_clock::now() + ttl;
}

bool is_expired_message_expiration(std::chrono::time_point<std::chrono::system_clock> expiration) {
    return expiration < std::chrono::system_clock::now();
}

}  // namespace silkworm::sentry::discovery::disc_v4::disc_v4_common
