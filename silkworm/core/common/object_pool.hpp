// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <stack>
#include <vector>

#ifndef __wasm__
#include <mutex>
#endif

#include <gsl/pointers>

#ifndef __wasm__
#define SILKWORM_DETAIL_OBJECT_POOL_GUARD \
    std::unique_lock<std::mutex> lock;    \
    if (thread_safe_) {                   \
        lock = std::unique_lock{mutex_};  \
    }
#else
#define SILKWORM_DETAIL_OBJECT_POOL_GUARD
#endif

namespace silkworm {

template <class T, class TDtor = std::default_delete<T>>
class ObjectPool {
  public:
    explicit ObjectPool(bool thread_safe = false) : thread_safe_{thread_safe} {}

    // Not copyable nor movable
    ObjectPool(const ObjectPool&) = delete;
    ObjectPool& operator=(const ObjectPool&) = delete;

    void add(gsl::owner<T*> t) {
        SILKWORM_DETAIL_OBJECT_POOL_GUARD
        pool_.push({t, TDtor()});
    }

    gsl::owner<T*> acquire() {
        SILKWORM_DETAIL_OBJECT_POOL_GUARD
        if (pool_.empty()) {
            return nullptr;
        }
        gsl::owner<T*> ret(pool_.top().release());
        pool_.pop();
        return ret;
    }

    bool empty() const {
        SILKWORM_DETAIL_OBJECT_POOL_GUARD
        return pool_.empty();
    }

    size_t size() const {
        SILKWORM_DETAIL_OBJECT_POOL_GUARD
        return pool_.size();
    }

  private:
    using PointerType = std::unique_ptr<T, TDtor>;

    std::stack<PointerType, std::vector<PointerType>> pool_{};

    bool thread_safe_{false};

#ifndef __wasm__
    mutable std::mutex mutex_;
#endif
};

}  // namespace silkworm
