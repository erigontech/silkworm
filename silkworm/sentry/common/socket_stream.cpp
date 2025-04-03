// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "socket_stream.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <silkworm/core/common/endian.hpp>

namespace silkworm::sentry {

using namespace boost::asio;

Task<void> SocketStream::send(Bytes data) {
    co_await async_write(socket_, buffer(data), use_awaitable);
}

Task<uint16_t> SocketStream::receive_short() {
    Bytes data = co_await receive_fixed(sizeof(uint16_t));
    uint16_t value = endian::load_big_u16(data.data());
    co_return value;
}

Task<Bytes> SocketStream::receive_fixed(size_t size) {
    Bytes data(size, 0);
    co_await async_read(socket_, buffer(data), use_awaitable);
    co_return std::move(data);
}

Task<ByteView> SocketStream::receive_size_and_data(Bytes& raw_data) {
    raw_data.resize(sizeof(uint16_t));
    co_await async_read(socket_, buffer(raw_data), use_awaitable);
    uint16_t size = endian::load_big_u16(raw_data.data());

    raw_data.resize(raw_data.size() + size);
    auto data_ptr = raw_data.data() + sizeof(uint16_t);
    co_await async_read(socket_, buffer(data_ptr, size), use_awaitable);

    co_return ByteView(data_ptr, size);
}

}  // namespace silkworm::sentry
