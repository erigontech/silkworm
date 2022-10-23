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

// Portions of the following code are based on Aeron [https://github.com/real-logic/aeron]

/*
 * Copyright 2014-2022 Real Logic Limited.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <chrono>
#include <limits>
#include <memory>
#include <string>
#include <thread>

#include <absl/strings/string_view.h>

namespace silkworm::rpc {

using namespace std::chrono_literals;  // NOLINT(build/namespaces)

class SleepingWaitStrategy {
  public:
    explicit SleepingWaitStrategy(std::chrono::milliseconds duration = 1ms) : duration_(duration) {}

    inline void idle(int work_count) {
        if (work_count > 0) {
            return;
        }

        std::this_thread::sleep_for(duration_);
    }

  private:
    std::chrono::milliseconds duration_;
};

class YieldingWaitStrategy {
  public:
    inline void idle(int work_count) {
        if (work_count > 0) {
            return;
        }

        std::this_thread::yield();
    }
};

class BusySpinWaitStrategy {
  public:
    inline void idle(int /*work_count*/) {
    }
};

enum class WaitMode {
    backoff, /* Wait strategy implemented in asio-grpc's agrpc::run */
    blocking,
    sleeping,
    yielding,
    busy_spin
};

bool AbslParseFlag(absl::string_view text, WaitMode* wait_mode, std::string* error);
std::string AbslUnparseFlag(WaitMode wait_mode);

}  // namespace silkworm::rpc
