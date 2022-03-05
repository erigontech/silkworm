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

#ifndef SILKWORM_COMMON_OBJECTPOOL_HPP_
#define SILKWORM_COMMON_OBJECTPOOL_HPP_

#include <iostream>
#include <memory>
#include <stack>

namespace silkworm {

template <class T, class TDtor = std::default_delete<T>>
class ObjectPool {
  public:
    using ptr_t = std::unique_ptr<T, TDtor>;

    ObjectPool() = default;

    [[maybe_unused]] explicit ObjectPool(size_t max_size) : max_size_{max_size} {
        std::vector<ptr_t> vec;
        vec.reserve(max_size_);
        pool_ = std::stack<ptr_t, std::vector<ptr_t>>{std::move(vec)};
    };

    virtual ~ObjectPool() = default;

    bool add(T*& t) {
        if (max_size_ && pool_.size() >= max_size_) {
            return false;
        }
        auto* tmp = t;
        t = nullptr;
        pool_.push(ptr_t(tmp, TDtor()));
        return true;
    }

    T* acquire() {
        if (!empty()) {
            T* ret(pool_.top().release());
            pool_.pop();
            return ret;
        }
        return nullptr;
    }

    template <class T2>
    T* acquire_or(T2&& right) {
        static_assert(std::is_convertible_v<T2, T*>);
        if (auto t{acquire()}; t) {
            return t;
        }
        return std::forward<T2>(right);
    }

    [[nodiscard]] bool empty() const { return pool_.empty(); }

    [[nodiscard]] size_t size() const { return pool_.size(); }

    void clear() {
        while (!pool_.empty()) {
            pool_.pop();
        }
    }

  private:
    size_t max_size_{0};
    std::stack<ptr_t, std::vector<ptr_t>> pool_{};
};

}  // namespace silkworm

#endif  // SILKWORM_COMMON_OBJECTPOOL_HPP_
