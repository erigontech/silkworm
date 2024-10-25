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
