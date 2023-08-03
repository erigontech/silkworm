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

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

#include <silkworm/infra/concurrency/stoppable.hpp>

#include "async_thread.hpp"

namespace silkworm {

/*
 * Abstract interface for active components
 * i.e. component that have an infinite loop and need a dedicated thread to run the loop (if the application
 * has also other things to do).
 * Here we prefer not to provide a thread facility and let the user provide one more suitable to the context,
 * so perhaps a better name is LongRunningComponent.
 */
class ActiveComponent : public Stoppable {
  public:
    virtual void execution_loop() = 0;

    boost::asio::awaitable<void> async_run(std::optional<std::size_t> stack_size = {}) {
        auto run = [this] { this->execution_loop(); };
        auto stop = [this] { this->stop(); };
        co_await concurrency::async_thread(std::move(run), std::move(stop), stack_size);
    }
};

}  // namespace silkworm
