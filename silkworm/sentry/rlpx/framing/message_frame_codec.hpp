// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdexcept>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/message.hpp>

namespace silkworm::sentry::rlpx::framing {

class MessageFrameCodec {
  public:
    Bytes encode(const Message& message) const;
    Message decode(ByteView frame_data) const;

    void enable_compression() { is_compression_enabled_ = true; }

    class DecompressionError : public std::runtime_error {
      public:
        DecompressionError() : std::runtime_error("MessageFrameCodec: invalid snappy data") {}
    };

    static const size_t kMaxFrameSize;

  private:
    bool is_compression_enabled_{false};
};

}  // namespace silkworm::sentry::rlpx::framing
