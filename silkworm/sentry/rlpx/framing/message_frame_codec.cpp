// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "message_frame_codec.hpp"

#include <snappy.h>

#include <stdexcept>
#include <string>

#include <silkworm/core/rlp/decode.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>

namespace silkworm::sentry::rlpx::framing {

const size_t MessageFrameCodec::kMaxFrameSize = 16 << 20;

static Bytes snappy_compress(ByteView data) {
    Bytes output;
    output.resize(snappy::MaxCompressedLength(data.size()));

    size_t compressed_length{0};
    snappy::RawCompress(
        reinterpret_cast<const char*>(data.data()),
        data.size(),
        reinterpret_cast<char*>(output.data()),
        &compressed_length);

    output.resize(compressed_length);
    return output;
}

static size_t snappy_uncompressed_length(ByteView data) {
    size_t uncompressed_length{0};
    bool ok = snappy::GetUncompressedLength(
        reinterpret_cast<const char*>(data.data()),
        data.size(),
        &uncompressed_length);
    if (!ok)
        throw std::runtime_error("MessageFrameCodec: invalid snappy uncompressed length");
    return uncompressed_length;
}

static Bytes snappy_decompress(ByteView data) {
    Bytes output;
    output.resize(snappy_uncompressed_length(data));

    bool ok = snappy::RawUncompress(
        reinterpret_cast<const char*>(data.data()),
        data.size(),
        reinterpret_cast<char*>(output.data()));
    if (!ok)
        throw MessageFrameCodec::DecompressionError();
    return output;
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

    uint8_t id{0};
    auto id_data = ByteView{frame_data.substr(0, 1)};
    success_or_throw(rlp::decode(id_data, id), "MessageFrameCodec: failed to decode a message ID");

    Bytes data;
    if (!is_compression_enabled_) {
        data = Bytes{frame_data.substr(1)};
    } else {
        if (snappy_uncompressed_length(frame_data.substr(1)) > kMaxFrameSize)
            throw std::runtime_error("MessageFrameCodec: uncompressed frame is too large");
        data = snappy_decompress(frame_data.substr(1));
    }

    return Message{id, std::move(data)};
}

}  // namespace silkworm::sentry::rlpx::framing
