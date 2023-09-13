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

#include <chrono>
#include <stdexcept>

#include <silkworm/infra/concurrency/task.hpp>

namespace silkworm::concurrency {

Task<void> timeout(
    std::chrono::milliseconds duration,
    const char* source_file_path = nullptr,
    int source_file_line = 0);

class TimeoutExpiredError : public std::runtime_error {
  public:
    TimeoutExpiredError() : std::runtime_error("Timeout has expired") {}
};

}  // namespace silkworm::concurrency

#define SILK_CONCURRENCY_TIMEOUT(duration) ::silkworm::concurrency::timeout(duration, __FILE__, __LINE__)
