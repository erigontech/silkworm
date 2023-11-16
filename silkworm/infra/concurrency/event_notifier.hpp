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

#include <variant>

#include "task.hpp"

#include <boost/asio/any_io_executor.hpp>

#include "channel.hpp"

namespace silkworm::concurrency {

// A simplified condition variable similar to Rust Tokio Notify:
// https://docs.rs/tokio/1.25.0/tokio/sync/struct.Notify.html
// Only one waiter is supported.
class EventNotifier {
  public:
    explicit EventNotifier(const boost::asio::any_io_executor& executor) : channel_(executor, 1) {}

    Task<void> wait() {
        co_await channel_.receive();
    }

    void notify() {
        channel_.try_send({});
    }

  private:
    Channel<std::monostate> channel_;
};

}  // namespace silkworm::concurrency
