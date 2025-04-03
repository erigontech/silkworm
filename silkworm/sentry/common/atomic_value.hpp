// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <mutex>

namespace silkworm::sentry {

template <typename T>
class AtomicValue {
  public:
    explicit AtomicValue(T value) : value_(std::move(value)) {}

    void set(T value) {
        std::scoped_lock lock(mutex_);
        value_ = value;
    }

    T get() {
        std::scoped_lock lock(mutex_);
        return value_;
    }

    std::function<T()> getter() {
        return [this] { return this->get(); };
    }

  private:
    T value_;
    std::mutex mutex_;
};

}  // namespace silkworm::sentry