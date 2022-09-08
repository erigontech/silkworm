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

#include "message_stream.hpp"

#include "message_frame_codec.hpp"

namespace silkworm::sentry::rlpx::framing {

boost::asio::awaitable<void> MessageStream::send(common::Message message) {
    co_await stream_.send(cipher_.encrypt_frame(message_frame_codec_.encode(message)));
}

boost::asio::awaitable<common::Message> MessageStream::receive() {
    Bytes header_data = co_await stream_.receive_fixed(FramingCipher::header_size());
    size_t header_frame_size = cipher_.decrypt_header(header_data);

    size_t frame_size = FramingCipher::frame_size(header_frame_size);
    if (frame_size > MessageFrameCodec::kMaxFrameSize)
        throw std::runtime_error("MessageStream: frame is too large");

    Bytes encrypted_frame_data = co_await stream_.receive_fixed(frame_size);
    Bytes frame_data = cipher_.decrypt_frame(encrypted_frame_data, header_frame_size);

    co_return message_frame_codec_.decode(frame_data);
}

void MessageStream::enable_compression() {
    message_frame_codec_.enable_compression();
}

}  // namespace silkworm::sentry::rlpx::framing
