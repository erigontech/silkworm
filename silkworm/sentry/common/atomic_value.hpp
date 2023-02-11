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

#pragma once

#include <functional>
#include <mutex>

namespace silkworm::sentry::common {

template <typename T>
class AtomicValue {
  public:
    explicit AtomicValue(T value) : value_(std::move(value)) {}

    void set(T value) {
        std::scoped_lock lock(mutex_);
        value_ = value;
    }

    [[nodiscard]] T get() {
        std::scoped_lock lock(mutex_);
        return value_;
    }

    [[nodiscard]] std::function<T()> getter() {
        return [this] { return this->get(); };
    }

  private:
    T value_;
    std::mutex mutex_;
};

}  // namespace silkworm::sentry::common