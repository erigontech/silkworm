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

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace silkworm::sentry {

class SocketStream {
  public:
    explicit SocketStream(const boost::asio::any_io_executor& executor) : socket_(executor) {}

    SocketStream(SocketStream&&) = default;
    SocketStream& operator=(SocketStream&&) noexcept = default;

    [[nodiscard]] boost::asio::ip::tcp::socket& socket() { return socket_; }
    [[nodiscard]] const boost::asio::ip::tcp::socket& socket() const { return socket_; }

    Task<void> send(Bytes data);

    Task<uint16_t> receive_short();
    Task<Bytes> receive_fixed(size_t size);
    Task<ByteView> receive_size_and_data(Bytes& raw_data);

  private:
    boost::asio::ip::tcp::socket socket_;
};

}  // namespace silkworm::sentry
