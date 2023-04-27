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

#include <stdexcept>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>

namespace silkworm::concurrency {

namespace asio = boost::asio;

// An awaitable-friendly future/promise

template <typename T>
class AwaitablePromise;

template <typename T>
class AwaitableFuture {
  public:
    AwaitableFuture(const AwaitableFuture&) = delete;
    AwaitableFuture(AwaitableFuture&& orig) : channel_(std::move(orig.channel_)) {}

    template <typename CompletionToken>
    auto get(CompletionToken completion_token) {
        return channel_->async_receive(completion_token);
    }

    T get() {
        return channel_->async_receive(asio::use_future).get();
    }

  private:
    friend class AwaitablePromise<T>;

    using AsyncChannel = asio::experimental::concurrent_channel<void(std::exception_ptr, T)>;

    explicit AwaitableFuture(std::shared_ptr<AsyncChannel> channel) : channel_(channel) {}

    std::shared_ptr<AsyncChannel> channel_;
};

template <typename T>
class AwaitablePromise {
    inline static size_t one_shot_channel = 1;
    using AsyncChannel = typename AwaitableFuture<T>::AsyncChannel;

  public:
    explicit AwaitablePromise(asio::any_io_executor&& executor) : channel_(std::make_shared<AsyncChannel>(executor, one_shot_channel)) {}
    explicit AwaitablePromise(asio::any_io_executor& executor) : channel_(std::make_shared<AsyncChannel>(executor, one_shot_channel)) {}
    explicit AwaitablePromise(asio::io_context& io_context) : channel_(std::make_shared<AsyncChannel>(io_context, one_shot_channel)) {}

    AwaitablePromise(const AwaitablePromise&) = delete;
    AwaitablePromise(AwaitablePromise&& orig) : channel_(std::move(orig.channel_)) {}

    template <typename CompletionToken>
    auto set_value(T value, CompletionToken completion_token) {
        return channel_->async_send(nullptr, std::move(value), completion_token);
    }

    void set_value(T value) {
        bool sent = channel_->try_send(nullptr, std::move(value));
        if (!sent) throw std::runtime_error("AwaitablePromise::set_value: channel is full");
    }

    template <typename CompletionToken>
    auto set_exception(std::exception_ptr ptr, CompletionToken completion_token) {
        return channel_->async_send(ptr, T{}, completion_token);
    }
    void set_exception(std::exception_ptr ptr) {
        bool sent = channel_->try_send(ptr, T{});
        if (!sent) throw std::runtime_error("AwaitablePromise::set_exception: channel is full");
    }

    AwaitableFuture<T> get_future() { return AwaitableFuture<T>(channel_); }

  private:
    std::shared_ptr<AsyncChannel> channel_;
};

}  // namespace silkworm::concurrency
