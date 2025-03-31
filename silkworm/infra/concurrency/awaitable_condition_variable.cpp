// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
        size_t waiter_version{0};
        {
            std::scoped_lock lock(mutex_);
            waiter_version = version_;
        }

        return [this, waiter_version]() -> Task<void> {
            auto executor = co_await boost::asio::this_coro::executor;

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
        ++version_;
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
    [[maybe_unused]] int non_trivial_destructor{0};  // silent clang-tidy
}

std::function<Task<void>()> AwaitableConditionVariable::waiter() {
    return p_impl_->waiter();
}

void AwaitableConditionVariable::notify_all() {
    p_impl_->notify_all();
}

}  // namespace silkworm::concurrency
