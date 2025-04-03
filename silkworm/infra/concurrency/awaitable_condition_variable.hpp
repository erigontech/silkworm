// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
