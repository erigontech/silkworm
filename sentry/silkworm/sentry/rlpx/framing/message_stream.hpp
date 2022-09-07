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

#include <boost/asio/awaitable.hpp>

#include <silkworm/sentry/common/message.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>

#include "framing_cipher.hpp"
#include "message_frame_codec.hpp"

namespace silkworm::sentry::rlpx::framing {

class MessageStream {
  public:
    MessageStream(FramingCipher cipher, common::SocketStream& stream)
        : cipher_(std::move(cipher)),
          stream_(stream) {}

    MessageStream(MessageStream&&) = default;

    boost::asio::awaitable<void> send(common::Message message);
    boost::asio::awaitable<common::Message> receive();

    void enable_compression();

  private:
    FramingCipher cipher_;
    common::SocketStream& stream_;
    MessageFrameCodec message_frame_codec_;
};

}  // namespace silkworm::sentry::rlpx::framing
