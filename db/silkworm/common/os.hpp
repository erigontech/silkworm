/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_DB_OS_HPP_
#define SILKWORM_DB_OS_HPP_

#include <stddef.h>

#if defined(_WIN32) || defined(_WIN64)

#include <Windows.h>
#include <sysinfoapi.h>

#else

#include <unistd.h>

#endif  // _WIN32 || defined(_WIN64)

namespace silkworm::os {

static inline size_t get_syspagesize(void) {
#if defined(_WIN32) || defined(_WIN64)

    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return static_cast<size_t>(info.dwPageSize);

#else

    return sysconf(_SC_PAGE_SIZE);

#endif
}

}  // namespace silkworm::os

#endif  // !SILKWORM_DB_OS_HPP_
