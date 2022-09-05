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

#include "socket_stream.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <silkworm/common/endian.hpp>

namespace silkworm::sentry::common {

using namespace boost::asio;

awaitable<void> SocketStream::send(Bytes data) {
    co_await async_write(socket_, buffer(data), use_awaitable);
}

awaitable<uint16_t> SocketStream::receive_short() {
    Bytes data = co_await receive_fixed(sizeof(uint16_t));
    uint16_t value = endian::load_big_u16(data.data());
    co_return value;
}

awaitable<Bytes> SocketStream::receive_fixed(std::size_t size) {
    Bytes data(size, 0);
    co_await async_read(socket_, buffer(data), use_awaitable);
    co_return std::move(data);
}

awaitable<ByteView> SocketStream::receive_size_and_data(Bytes& raw_data) {
    raw_data.resize(sizeof(uint16_t));
    co_await async_read(socket_, buffer(raw_data), use_awaitable);
    uint16_t size = endian::load_big_u16(raw_data.data());

    raw_data.resize(raw_data.size() + size);
    auto data_ptr = raw_data.data() + sizeof(uint16_t);
    co_await async_read(socket_, buffer(data_ptr, size), use_awaitable);

    co_return ByteView(data_ptr, size);
}

}  // namespace silkworm::sentry::common
