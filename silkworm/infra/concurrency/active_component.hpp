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

#include <atomic>
#include <optional>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/infra/concurrency/stoppable.hpp>

#include "async_thread.hpp"

namespace silkworm {

//! Abstract interface for active components i.e. components that have an infinite loop and need a dedicated thread
//! to run the loop (if the application has also other things to do).
class ActiveComponent : public Stoppable {
  public:
    virtual void execution_loop() = 0;

    //! This adapter method makes ActiveComponent suitable to be used as asynchronous task
    Task<void> async_run(const char* thread_name, std::optional<size_t> stack_size = {}) {
        auto run = [this] { this->execution_loop(); };
        auto stop = [this] { this->stop(); };
        co_await concurrency::async_thread(std::move(run), std::move(stop), thread_name, stack_size);
    }
};

}  // namespace silkworm
