/*
   Copyright 2020-2022 The Silkrpc Authors

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

// Portions of the following code are inspired by Aeron [https://github.com/real-logic/aeron]

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

// Portions of the following code are based on Disruptor-cpp [https://github.com/Abc-Arbitrage/Disruptor-cpp]

#pragma once

#include <chrono>
#include <limits>
#include <memory>
#include <string>
#include <thread>

#include <absl/strings/string_view.h>

namespace silkrpc {

// These wait strategies are experimental for performance tests and not yet production-ready.

class SleepingWaitStrategy {
  public:
    inline void idle(int work_count) {
        if (work_count > 0) {
            if (counter_ != kRetries) {
                counter_ = kRetries;
            }
            return;
        }

        if (counter_ > 100) {
            --counter_;
        } else if (counter_ > 0) {
            --counter_;
            std::this_thread::yield();
        } else {
            std::this_thread::sleep_for(duration_);
        }
    }

  private:
    inline static const int kRetries{200};

    int counter_{kRetries};
    std::chrono::milliseconds duration_{1};
};

class YieldingWaitStrategy {
  public:
    inline void idle(int work_count) {
        if (work_count > 0) {
            if (counter_ != kSpinTries) {
                counter_ = kSpinTries;
            }
            return;
        }

        if (counter_ == 0) {
            std::this_thread::yield();
        } else {
            --counter_;
        }
    }

  private:
    inline static const int kSpinTries{100};

    int counter_{kSpinTries};
};

class SpinWaitWaitStrategy {
  public:
    inline void idle(int work_count) {
        if (work_count > 0) {
            if (counter_ != 0) {
                counter_ = 0;
            }
            return;
        }

        if (counter_ > kYieldThreshold) {
            auto delta = counter_ - kYieldThreshold;
            if (delta % kSleep1EveryHowManyTimes == kSleep1EveryHowManyTimes - 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            } else if (delta % kSleep0EveryHowManyTimes == kSleep0EveryHowManyTimes - 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(0));
            } else {
                std::this_thread::yield();
            }
        } else {
            for (auto i{0}; i < (4 << counter_); i++) {
                spin_wait();
            }
        }

        if (counter_ == std::numeric_limits<int32_t>::max()) {
            counter_ = kYieldThreshold;
        } else {
            ++counter_;
        }
    }

  private:
    inline void spin_wait() {
    }

    inline static const int32_t kYieldThreshold{10};
    inline static const int32_t kSleep0EveryHowManyTimes{5};
    inline static const int32_t kSleep1EveryHowManyTimes{20};

    int32_t counter_{0};
};

class BusySpinWaitStrategy {
  public:
    inline void idle(int /*work_count*/) {
    }
};

enum class WaitMode {
    backoff,    /* Wait strategy implemented in asio-grpc's agrpc::run */
    blocking,   /* Custom multi-thread wait strategy implemented here */
    sleeping,   /* Custom single-thread wait strategies implemented here */
    yielding,
    spin_wait,
    busy_spin
};

bool AbslParseFlag(absl::string_view text, WaitMode* wait_mode, std::string* error);
std::string AbslUnparseFlag(WaitMode wait_mode);

} // namespace silkrpc

