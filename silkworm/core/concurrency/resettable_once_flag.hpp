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

#include <functional>
#include <utility>

#ifdef SILKWORM_CORE_USE_ABSEIL
#include <absl/base/call_once.h>
#endif

namespace silkworm {

#ifdef SILKWORM_CORE_USE_ABSEIL

// Resettable once_flag. Helper class for lazy evaluation of derived fields such as transaction hash & sender.
// On one hand, we want such evaluation to happen exactly once and be safe to invoke concurrently (call_once).
// On the other hand, we need to re-calculate when the inputs to the evaluation change (thus resettable).
// N.B. This version is based on absl::call_once.
class ResettableOnceFlag {
  public:
    constexpr ResettableOnceFlag() = default;

    ResettableOnceFlag(const ResettableOnceFlag& other) {
        const uint32_t other_flag{other.flag_.load(std::memory_order_acquire)};
        if (other_flag == absl::base_internal::kOnceDone) {
            flag_.store(absl::base_internal::kOnceDone, std::memory_order_release);
        } else {
            // Have to re-evaluate if the other is in the middle of calculations (other_flag == kOnceRunning || kOnceWaiter)
            flag_.store(0, std::memory_order_release);
        }
    }
    ResettableOnceFlag& operator=(const ResettableOnceFlag& other) {
        const uint32_t other_flag{other.flag_.load(std::memory_order_acquire)};
        if (other_flag == absl::base_internal::kOnceDone) {
            flag_.store(absl::base_internal::kOnceDone, std::memory_order_release);
        } else {
            // Have to re-evaluate if the other is in the middle of calculations (other_flag == kOnceRunning || kOnceWaiter)
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
        if (s != absl::base_internal::kOnceDone) [[unlikely]] {
            absl::base_internal::CallOnceImpl(
                once, absl::base_internal::SCHEDULE_COOPERATIVE_AND_KERNEL,
                std::forward<Callable>(fn), std::forward<Args>(args)...);
        }
    }

  private:
    std::atomic<uint32_t> flag_{0};
};

#else

// Warning: this version is only suitable for protecting lazy fields in a single-threaded environment.
// In a multi-threaded environment use the Abseil-based version above.
class ResettableOnceFlag {
  public:
    constexpr ResettableOnceFlag() = default;

    ResettableOnceFlag(const ResettableOnceFlag&) = default;
    ResettableOnceFlag& operator=(const ResettableOnceFlag&) = default;

    void reset() { done_ = false; }

    template <typename Callable, typename... Args>
    void call_once(Callable&& fn, Args&&... args) {
        if (!done_) {
            std::invoke(std::forward<Callable>(fn), std::forward<Args>(args)...);
            done_ = true;
        }
    }

  private:
    bool done_{false};
};

#endif

}  // namespace silkworm
