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

#include <cassert>
#include <mutex>
#include <optional>
#include <stdexcept>

#include <silkworm/node/concurrency/coroutine.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>

#include <silkworm/node/concurrency/channel.hpp>

#include "atomic_value.hpp"

namespace silkworm::sentry::common {

// An awaitable-friendly promise.
// See also: https://docs.rs/tokio/1.25.0/tokio/sync/oneshot/index.html
template <typename T>
class Promise {
  public:
    explicit Promise(boost::asio::any_io_executor&& executor) : channel_(executor, 1) {}
    explicit Promise(boost::asio::any_io_executor& executor) : channel_(executor, 1) {}
    explicit Promise(boost::asio::io_context& io_context) : channel_(io_context, 1) {}

    boost::asio::awaitable<T> wait() {
        std::unique_lock lock{mutex_, std::defer_lock};
        if (!lock.try_lock()) {
            assert(false);
            throw std::runtime_error("Promise result is already awaited");
        }

        auto ready_value = value_.get();
        if (ready_value) {
            co_return ready_value.value();
        }

        T value = co_await channel_.receive();
        value_.set(value);
        co_return value;
    }

    void set_value(T value) {
        channel_.try_send(std::move(value));
    }

  private:
    AtomicValue<std::optional<T>> value_{std::nullopt};
    concurrency::Channel<T> channel_;
    std::mutex mutex_;
};

}  // namespace silkworm::sentry::common
