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

#include <memory>
#include <mutex>

namespace silkworm {

class ResettableOnceFlag {
  public:
    ResettableOnceFlag() {
        reset();
    }

    ResettableOnceFlag(const ResettableOnceFlag&) {
        reset();
    }
    ResettableOnceFlag& operator=(const ResettableOnceFlag&) {
        reset();
        return *this;
    }

    ResettableOnceFlag(ResettableOnceFlag&&) = default;
    ResettableOnceFlag& operator=(ResettableOnceFlag&&) = default;

    [[nodiscard]] std::once_flag& get() { return *flag_; }

    void reset() {
        flag_ = std::make_unique<std::once_flag>();
    }

  private:
    std::unique_ptr<std::once_flag> flag_;
};

}  // namespace silkworm
