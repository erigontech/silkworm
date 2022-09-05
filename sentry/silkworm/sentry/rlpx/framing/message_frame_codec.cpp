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

#include "message_frame_codec.hpp"

#include <silkworm/rlp/decode.hpp>
#include <silkworm/rlp/encode.hpp>

namespace silkworm::sentry::rlpx::framing {

using common::Message;

static Bytes snappy_compress(ByteView data) {
    // TODO
    return Bytes{data};
}

static Bytes snappy_decompress(ByteView data) {
    // TODO
    return Bytes{data};
}

Bytes MessageFrameCodec::encode(const Message& message) const {
    Bytes frame_data;
    frame_data.reserve(message.data.size() + 1);

    rlp::encode(frame_data, message.id);

    if (!is_compression_enabled_) {
        frame_data += message.data;
    } else {
        frame_data += snappy_compress(message.data);
    }

    return frame_data;
}

Message MessageFrameCodec::decode(ByteView frame_data) const {
    if (frame_data.empty())
        throw std::runtime_error("MessageFrameCodec: frame size too short");

    uint8_t id;
    auto id_data = ByteView{frame_data.substr(0, 1)};
    auto err = rlp::decode(id_data, id);
    if (err != DecodingResult::kOk)
        throw std::runtime_error("MessageFrameCodec: failed to decode a message ID");

    Bytes data;
    if (!is_compression_enabled_) {
        data = Bytes{frame_data.substr(1)};
    } else {
        data = snappy_decompress(frame_data.substr(1));
    }

    return Message{id, std::move(data)};
}

}  // namespace silkworm::sentry::rlpx::framing
