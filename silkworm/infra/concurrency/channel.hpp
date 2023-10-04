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

#include <optional>

#include "task.hpp"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

namespace silkworm::concurrency {

template <typename T>
class Channel {
  public:
    explicit Channel(boost::asio::any_io_executor executor) : channel_(std::move(executor)) {}
    Channel(boost::asio::any_io_executor executor, std::size_t max_buffer_size)
        : channel_(std::move(executor), max_buffer_size) {}

    Task<void> send(T value) {
        try {
            co_await channel_.async_send(boost::system::error_code(), value, boost::asio::use_awaitable);
        } catch (const boost::system::system_error& ex) {
            if (ex.code() == boost::asio::experimental::error::channel_cancelled)
                throw boost::system::system_error(make_error_code(boost::system::errc::operation_canceled));
            throw;
        }
    }

    bool try_send(T value) {
        return channel_.try_send(boost::system::error_code(), value);
    }

    Task<T> receive() {
        try {
            co_return (co_await channel_.async_receive(boost::asio::use_awaitable));
        } catch (const boost::system::system_error& ex) {
            if (ex.code() == boost::asio::experimental::error::channel_cancelled)
                throw boost::system::system_error(make_error_code(boost::system::errc::operation_canceled));
            throw;
        }
    }

    std::optional<T> try_receive() {
        std::optional<T> result;
        channel_.try_receive([&](const boost::system::error_code& error, T&& value) {
            if (error == boost::asio::experimental::error::channel_cancelled)
                throw boost::system::system_error(make_error_code(boost::system::errc::operation_canceled));
            if (error)
                throw boost::system::system_error(error);
            result = std::move(value);
        });
        return result;
    }

    void close() {
        channel_.close();
    }

  private:
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, T)> channel_;
};

}  // namespace silkworm::concurrency
