// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/sentry/common/message.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>

#include "framing_cipher.hpp"
#include "message_frame_codec.hpp"

namespace silkworm::sentry::rlpx::framing {

class MessageStream {
  public:
    MessageStream(FramingCipher cipher, SocketStream& stream)
        : cipher_(std::move(cipher)),
          stream_(stream) {}

    MessageStream(MessageStream&&) = default;

    Task<void> send(Message message);
    Task<Message> receive();

    void enable_compression();

    using DecompressionError = MessageFrameCodec::DecompressionError;

  private:
    FramingCipher cipher_;
    SocketStream& stream_;
    MessageFrameCodec message_frame_codec_;
};

}  // namespace silkworm::sentry::rlpx::framing
