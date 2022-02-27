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

template <class T>
class ObjectPool {
  public:
    using ptr_t = std::unique_ptr<T>;

    ObjectPool() = default;
    virtual ~ObjectPool() = default;

    void add(std::unique_ptr<T> t) { pool_.push(std::move(t)); }

    ptr_t acquire() {
        if (!empty()) {
            ptr_t tmp(pool_.top().release());
            pool_.pop();
            return tmp;
        }
        return {nullptr};
    }

    [[nodiscard]] bool empty() const { return pool_.empty(); }

    [[nodiscard]] size_t size() const { return pool_.size(); }

  private:
    std::stack<std::unique_ptr<T>> pool_;
};

}  // namespace silkworm

#endif  // SILKWORM_COMMON_OBJECTPOOL_HPP_
