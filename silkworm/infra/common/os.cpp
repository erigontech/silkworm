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

#include "os.hpp"

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>

#include <sys/resource.h>
#elif defined(_WIN32)
#include <windows.h>

#include <cstdio>
#include <limits>
#else
#pragma message("unsupported platform detected in test/os.cpp")
#endif

namespace silkworm::os {

uint64_t max_file_descriptors() {
    uint64_t max_descriptors{0};
#if defined(__linux__) || defined(__APPLE__)
    // Get the current limit
    rlimit limit{};
    const auto result = getrlimit(RLIMIT_NOFILE, &limit);
    if (result == -1) return 0;
    // Current max descriptors is *soft* limit (hard limit is max value of soft limit)
    max_descriptors = limit.rlim_cur;
#elif defined(_WIN32)
    max_descriptors = _getmaxstdio();
#endif
    return max_descriptors;
}

bool set_max_file_descriptors(uint64_t max_descriptors) {
#if defined(__linux__) || defined(__APPLE__)
    // Get the current limit
    rlimit limit{};
    const auto get_result = getrlimit(RLIMIT_NOFILE, &limit);
    if (get_result == -1) return false;
    // Try to update the *soft* limit (not over the hard limit i.e. max allowance)
    limit.rlim_cur = max_descriptors < limit.rlim_max ? max_descriptors : limit.rlim_max;
    const auto set_result = setrlimit(RLIMIT_NOFILE, &limit);
    return set_result == 0;
#elif defined(_WIN32)
    // Hard limit is hard-coded on Windows
    constexpr auto kMaxNumFiles = 8'192;
    // Try to update the *soft* limit (not over the hard limit i.e. max allowance)
    const int num_max_descriptors = max_descriptors < kMaxNumFiles ? static_cast<int>(max_descriptors) : kMaxNumFiles;
    const auto result = _setmaxstdio(num_max_descriptors);
    return result == num_max_descriptors;
#else
    (void)max_descriptors;
    return false;
#endif
}

std::size_t page_size() noexcept {
    static auto system_page_size = []() -> std::size_t {
#ifdef _WIN32
        SYSTEM_INFO system_info;
        ::GetSystemInfo(&system_info);
        return static_cast<std::size_t>(system_info.dwPageSize);
#else
        return static_cast<std::size_t>(::getpagesize());
#endif  // _WIN32
    }();
    return system_page_size;
}

}  // namespace silkworm::os
