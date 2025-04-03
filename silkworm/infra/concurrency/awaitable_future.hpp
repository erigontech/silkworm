// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>
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

    Task<T> get() {
        try {
            std::optional<T> result = co_await channel_->async_receive(boost::asio::use_awaitable);
            co_return std::move(result.value());
        } catch (const boost::system::system_error& ex) {
            close_and_throw_if_cancelled(ex);
            throw ex;
        }
    }

    Task<T> get_async() {
        return get();
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
        : channel_(std::make_shared<AsyncChannel>(executor, 1)),
          subscribed_(std::make_unique<std::atomic_bool>()) {}

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

    AwaitableFuture<T> get_future() {
        bool expected{false};
        bool was_unsubscribed = subscribed_->compare_exchange_strong(expected, true);
        if (!was_unsubscribed)
            throw std::runtime_error("AwaitablePromise::get_future can't be called multiple times");
        return AwaitableFuture<T>(channel_);
    }

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
    std::unique_ptr<std::atomic_bool> subscribed_;
};

}  // namespace silkworm::concurrency
