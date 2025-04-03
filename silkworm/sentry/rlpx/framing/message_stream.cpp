// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "message_stream.hpp"

#include <stdexcept>

#include "message_frame_codec.hpp"

namespace silkworm::sentry::rlpx::framing {

Task<void> MessageStream::send(Message message) {
    co_await stream_.send(cipher_.encrypt_frame(message_frame_codec_.encode(message)));
}

Task<Message> MessageStream::receive() {
    Bytes header_data = co_await stream_.receive_fixed(FramingCipher::header_size());
    size_t header_frame_size = cipher_.decrypt_header(header_data);

    size_t frame_size = FramingCipher::frame_size(header_frame_size);
    if (frame_size > MessageFrameCodec::kMaxFrameSize)
        throw std::runtime_error("rlpx::framing::MessageStream: frame is too large");

    Bytes encrypted_frame_data = co_await stream_.receive_fixed(frame_size);
    Bytes frame_data = cipher_.decrypt_frame(encrypted_frame_data, header_frame_size);

    co_return message_frame_codec_.decode(frame_data);
}

void MessageStream::enable_compression() {
    message_frame_codec_.enable_compression();
}

}  // namespace silkworm::sentry::rlpx::framing
