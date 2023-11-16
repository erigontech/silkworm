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

#include "awaitable_condition_variable.hpp"

#include <mutex>
#include <set>
#include <tuple>

#include <boost/asio/this_coro.hpp>

#include "event_notifier.hpp"

namespace silkworm::concurrency {

class AwaitableConditionVariableImpl {
  public:
    std::function<Task<void>()> waiter() {
        size_t waiter_version;
        {
            std::scoped_lock lock(mutex_);
            waiter_version = version_;
        }

        return [this, waiter_version]() -> Task<void> {
            auto executor = co_await boost::asio::this_coro::executor;  // NOLINT(clang-analyzer-core.CallAndMessage)

            decltype(waiters_)::iterator waiter;
            {
                std::scoped_lock lock(mutex_);

                // if notify_all was called while preparing for waiting
                // we need to wake up to avoid a deadlock
                if (waiter_version != version_) {
                    co_return;
                }

                std::tie(waiter, std::ignore) = waiters_.insert(std::make_unique<EventNotifier>(executor));
            }

            co_await (*waiter)->wait();

            {
                std::scoped_lock lock(mutex_);
                waiters_.erase(waiter);
            }
        };
    }

    void notify_all() {
        std::scoped_lock lock(mutex_);
        version_++;
        for (auto& waiter : waiters_) {
            waiter->notify();
        }
    }

  private:
    std::mutex mutex_;
    std::set<std::unique_ptr<EventNotifier>> waiters_;
    size_t version_{0};
};

AwaitableConditionVariable::AwaitableConditionVariable() : p_impl_(std::make_unique<AwaitableConditionVariableImpl>()) {
}

AwaitableConditionVariable::~AwaitableConditionVariable() {
    [[maybe_unused]] int non_trivial_destructor;  // silent clang-tidy
}

std::function<Task<void>()> AwaitableConditionVariable::waiter() {
    return p_impl_->waiter();
}

void AwaitableConditionVariable::notify_all() {
    p_impl_->notify_all();
}

}  // namespace silkworm::concurrency
