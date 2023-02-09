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

#include <iostream>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/resource.h>
#elif defined(_WIN32)
#include <cstdio>
#else
#pragma message("unsupported platform detected in test/os.hpp")
#endif

namespace silkworm::test {

//! Low-level OS utilities
class OS {
  public:
    static uint64_t max_file_descriptors() {
        uint64_t max_descriptors;
#if defined(__linux__) || defined(__APPLE__)
        rlimit limit{};
        getrlimit(RLIMIT_NOFILE, &limit);
        max_descriptors = limit.rlim_cur;
#elif defined(_WIN32)
        max_descriptors = _getmaxstdio();
#else
        max_descriptors = 0;
#endif
        return max_descriptors;
    }
};

}  // namespace silkworm::test
