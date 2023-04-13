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

#include <limits>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/resource.h>
#elif defined(_WIN32)
#include <cstdio>
#include <limits>
#else
#pragma message("unsupported platform detected in test/os.cpp")
#endif

namespace silkworm::os {

uint64_t max_file_descriptors() {
    uint64_t max_descriptors;
#if defined(__linux__) || defined(__APPLE__)
    rlimit limit{};
    getrlimit(RLIMIT_NOFILE, &limit);
    max_descriptors = limit.rlim_max;
#elif defined(_WIN32)
    max_descriptors = _getmaxstdio();
#else
    max_descriptors = 0;
#endif
    return max_descriptors;
}

bool set_max_file_descriptors(uint64_t max_descriptors) {
#if defined(__linux__) || defined(__APPLE__)
    rlimit limit{
        .rlim_max = max_descriptors,
    };
    const auto result = setrlimit(RLIMIT_NOFILE, &limit);
    return result == 0;
#elif defined(_WIN32)
    const auto max_int = std::numeric_limits<int>::max();
    int num_max_descriptors = max_descriptors > max_int ? max_int : static_cast<int>(max_descriptors);
    const auto result = _setmaxstdio(num_max_descriptors);
    return result == num_max_descriptors;
#else
    (void)max_descriptors;
    return false;
#endif
}

}  // namespace silkworm::os
