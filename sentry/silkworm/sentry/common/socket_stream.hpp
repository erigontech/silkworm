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

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <silkworm/common/base.hpp>

namespace silkworm::sentry::common {

class SocketStream {
  public:
    explicit SocketStream(boost::asio::io_context& io_context) : socket_(io_context) {}
    explicit SocketStream(boost::asio::any_io_executor& executor) : socket_(executor) {}

    SocketStream(SocketStream&&) = default;
    SocketStream& operator=(SocketStream&&) = default;

    [[nodiscard]] boost::asio::ip::tcp::socket& socket() { return socket_; }

    boost::asio::awaitable<void> send(Bytes data);

    boost::asio::awaitable<uint16_t> receive_short();
    boost::asio::awaitable<Bytes> receive_fixed(std::size_t size);
    boost::asio::awaitable<ByteView> receive_size_and_data(Bytes& raw_data);

  private:
    boost::asio::ip::tcp::socket socket_;
};

}  // namespace silkworm::sentry::common
