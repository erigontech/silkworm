// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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

    boost::asio::ip::tcp::socket& socket() { return socket_; }
    const boost::asio::ip::tcp::socket& socket() const { return socket_; }

    Task<void> send(Bytes data);

    Task<uint16_t> receive_short();
    Task<Bytes> receive_fixed(size_t size);
    Task<ByteView> receive_size_and_data(Bytes& raw_data);

  private:
    boost::asio::ip::tcp::socket socket_;
};

}  // namespace silkworm::sentry
