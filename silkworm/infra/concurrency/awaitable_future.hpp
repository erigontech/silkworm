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

#include <optional>
#include <stdexcept>
#include <utility>

#include "task.hpp"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>

namespace silkworm::concurrency {

// An awaitable-friendly future/promise
// See also: https://docs.rs/tokio/1.25.0/tokio/sync/oneshot/index.html

template <typename T>
class AwaitablePromise;

template <typename T>
class AwaitableFuture {
  public:
    AwaitableFuture(const AwaitableFuture&) = delete;
    AwaitableFuture& operator=(const AwaitableFuture&) = delete;

    AwaitableFuture(AwaitableFuture&&) noexcept = default;
    AwaitableFuture& operator=(AwaitableFuture&&) noexcept = default;

    Task<T> get_async() {
        try {
            std::optional<T> result = co_await channel_->async_receive(boost::asio::use_awaitable);
            co_return std::move(result.value());
        } catch (const boost::system::system_error& ex) {
            close_and_throw_if_cancelled(ex);
            throw ex;
        }
    }

    T get() {
        try {
            std::optional<T> result = channel_->async_receive(boost::asio::use_future).get();
            return std::move(result.value());
        } catch (const boost::system::system_error& ex) {
            close_and_throw_if_cancelled(ex);
            throw ex;
        }
    }

  private:
    friend class AwaitablePromise<T>;

    using AsyncChannel = boost::asio::experimental::concurrent_channel<void(std::exception_ptr, std::optional<T>)>;

    explicit AwaitableFuture(std::shared_ptr<AsyncChannel> channel) : channel_(std::move(channel)) {}

    void close_and_throw_if_cancelled(const boost::system::system_error& ex) {
        // Convert channel cancelled into operation cancelled to allow just one catch clause at call site
        if (ex.code() == boost::asio::experimental::channel_errc::channel_cancelled) {
            // Close the channel because cancellation state seems to be not detectable at sender side
            channel_->close();
            throw boost::system::system_error{make_error_code(boost::system::errc::operation_canceled)};
        }
    }

    std::shared_ptr<AsyncChannel> channel_;
};

template <typename T>
class AwaitablePromise {
    using AsyncChannel = typename AwaitableFuture<T>::AsyncChannel;

  public:
    explicit AwaitablePromise(const boost::asio::any_io_executor& executor)
        : channel_(std::make_shared<AsyncChannel>(executor, 1)) {}

    AwaitablePromise(const AwaitablePromise&) = delete;
    AwaitablePromise& operator=(const AwaitablePromise&) = delete;

    AwaitablePromise(AwaitablePromise&&) noexcept = default;
    AwaitablePromise& operator=(AwaitablePromise&&) noexcept = default;

    bool set_value(T value) {
        return set(nullptr, std::move(value));
    }

    void set_exception(std::exception_ptr ptr) {
        set(ptr, std::nullopt);
    }

    AwaitableFuture<T> get_future() { return AwaitableFuture<T>(channel_); }

    class AlreadySatisfiedError : public std::runtime_error {
      public:
        AlreadySatisfiedError() : std::runtime_error("AwaitablePromise is already satisfied") {}
    };

  private:
    bool set(std::exception_ptr ptr, std::optional<T> value) {
        const bool sent = channel_->try_send(ptr, std::move(value));
        // Any send failure when channel has already been closed must not trigger an error
        if (!sent && channel_->is_open()) {
            throw AlreadySatisfiedError();
        }
        return sent;
    }

    std::shared_ptr<AsyncChannel> channel_;
};

}  // namespace silkworm::concurrency
