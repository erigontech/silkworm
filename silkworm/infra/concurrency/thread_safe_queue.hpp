// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <condition_variable>
#include <mutex>
#include <queue>

namespace silkworm {

template <typename T, template <typename S, typename Alloc = std::allocator<T> > class container = std::deque>
class ThreadSafeQueue {
  private:
    container<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable condition_variable_;

  public:
    void push(T const& data) {
        {
            std::unique_lock lock(mutex_);
            queue_.push_back(data);
        }  // lock.unlock();
        condition_variable_.notify_one();
    }

    void push(T&& data) {
        {
            std::unique_lock lock(mutex_);
            queue_.push_back(std::move(data));
        }  // lock.unlock();
        condition_variable_.notify_one();
    }

    bool empty() const {
        std::unique_lock lock(mutex_);
        return queue_.empty();
    }

    size_t size() const {
        std::unique_lock lock(mutex_);
        return queue_.size();
    }

    bool try_pop(T& popped_value) {
        std::unique_lock lock(mutex_);
        if (queue_.empty()) {
            return false;
        }

        popped_value = queue_.front();
        queue_.pop_front();
        return true;
    }

    void wait_and_pop(T& popped_value) {
        std::unique_lock lock(mutex_);
        condition_variable_.wait(lock, [this] { return !queue_.empty(); });
        popped_value = queue_.front();
        queue_.pop_front();
    }

    template <typename Duration>
    bool timed_wait_and_pop(T& popped_value, Duration const& wait_duration) {
        std::unique_lock lock(mutex_);
        if (!condition_variable_.wait_for(lock, wait_duration, [this] { return !queue_.empty(); })) {
            return false;
        }
        popped_value = queue_.front();
        queue_.pop_front();
        return true;
    }
};

}  // namespace silkworm
