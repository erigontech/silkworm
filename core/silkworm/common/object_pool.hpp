/*
   Copyright 2022 The Silkworm Authors

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

#ifndef SILKWORM_COMMON_OBJECT_POOL_HPP_
#define SILKWORM_COMMON_OBJECT_POOL_HPP_

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

    [[nodiscard]] bool empty() const {
        SILKWORM_DETAIL_OBJECT_POOL_GUARD
        return pool_.empty();
    }

    [[nodiscard]] size_t size() const {
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

#endif  // SILKWORM_COMMON_OBJECT_POOL_HPP_
