/*
   Copyright 2021-2022 The Silkworm Authors

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

#include "util.hpp"

namespace silkworm::etl {

std::string errno2str(int err_code) {
    char msg[64];
#if defined(_WIN32) || defined(_WIN64)
    if (strerror_s(msg, sizeof(msg), err_code) != 0) {
        (void)strncpy_s(msg, "Unknown error", _TRUNCATE);
    }
#else
    if (strerror_r(err_code, msg, sizeof(msg)) != 0) {
        (void)strncpy(msg, "Unknown error", sizeof(msg));
    }
#endif
    msg[sizeof(msg) - 1] = '\0';
    return {msg};
}

bool operator<(const Entry& a, const Entry& b) {
    auto diff{a.key.compare(b.key)};
    if (diff == 0) {
        return a.value < b.value;
    }
    return diff < 0;
}

}  // namespace silkworm::etl
