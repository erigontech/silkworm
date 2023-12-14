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

#pragma once

#include <absl/base/call_once.h>

namespace silkworm {

// Resettable absl::once_flag. Helper class for lazy evaluation of derived fields such as transaction hash & sender.
// On one hand, we want such evaluation to happen exactly once and be safe to invoke concurrently (absl::call_once).
// On the other hand, we need to re-calculate when the inputs to the evaluation change (thus resettable).
class ResettableOnceFlag {
  public:
    constexpr ResettableOnceFlag() {}

    ResettableOnceFlag(const ResettableOnceFlag& other) {
        const uint32_t s{other.flag_.load(std::memory_order_acquire)};
        if (s == absl::base_internal::kOnceDone) {
            flag_.store(absl::base_internal::kOnceDone, std::memory_order_release);
        } else {
            flag_.store(0, std::memory_order_release);
        }
    }
    ResettableOnceFlag& operator=(const ResettableOnceFlag& other) {
        const uint32_t s{other.flag_.load(std::memory_order_acquire)};
        if (s == absl::base_internal::kOnceDone) {
            flag_.store(absl::base_internal::kOnceDone, std::memory_order_release);
        } else {
            flag_.store(0, std::memory_order_release);
        }
        return *this;
    }

    void reset() {
        flag_.store(0, std::memory_order_release);
    }

    template <typename Callable, typename... Args>
    void call_once(Callable&& fn, Args&&... args) {
        std::atomic<uint32_t>* once{&flag_};
        const uint32_t s{once->load(std::memory_order_acquire)};
        if (ABSL_PREDICT_FALSE(s != absl::base_internal::kOnceDone)) {
            absl::base_internal::CallOnceImpl(
                once, absl::base_internal::SCHEDULE_COOPERATIVE_AND_KERNEL,
                std::forward<Callable>(fn), std::forward<Args>(args)...);
        }
    }

  private:
    std::atomic<uint32_t> flag_{0};
};

}  // namespace silkworm
