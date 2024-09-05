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
#include <memory>

#include "task.hpp"

namespace silkworm::concurrency {

class AwaitableConditionVariableImpl;

/**

A simplified condition variable similar to Rust Tokio Notify:
https://docs.rs/tokio/1.25.0/tokio/sync/struct.Notify.html
It supports multiple waiters unlike EventNotifier.

Synchronize waiter()/notify_all() calls with your producer state to avoid a deadlock.
It happens if the producer readiness updates right before calling waiter().

Example:
    // consumers
    std::unique_lock lock{mutex_};
    if (ready_) co_return;
    auto waiter = cond_var.waiter();
    lock.unlock();
    co_await waiter();

    // producer
    std::scoped_lock lock{mutex_};
    ready_ = true;
    cond_var.notify_all();

 */
class AwaitableConditionVariable {
  public:
    AwaitableConditionVariable();
    virtual ~AwaitableConditionVariable();

    using Waiter = std::function<Task<void>()>;

    Waiter waiter();
    void notify_all();

  private:
    std::unique_ptr<AwaitableConditionVariableImpl> p_impl_;
};

}  // namespace silkworm::concurrency
