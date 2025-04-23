// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <zlib.h>
#include <memory>
#include <stdexcept>
#include <string>

namespace silkworm::rpc::http {

inline constexpr int kZlibCompressionBufferSize = 65536;

class ZlibCompressor {
  public:
    ZlibCompressor(const ZlibCompressor&) = delete;

    ZlibCompressor() {
        memset(&stream_, 0, sizeof(z_stream));
        stream_.zalloc = Z_NULL;
        stream_.zfree = Z_NULL;
        stream_.opaque = Z_NULL;

        if (deflateInit2(&stream_, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
            throw std::runtime_error("zlib initialization error");
        }
    }

    ~ZlibCompressor() {
        deflateEnd(&stream_);
    }

    void compress_chunk(const std::string& clear_data, std::string& compressed_data, const bool flush) {
        stream_.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(clear_data.data()));
        stream_.avail_in = clear_data.size();
        size_t offset = 0;
        do {
            compressed_data.resize(kZlibCompressionBufferSize + offset);

            stream_.next_out = reinterpret_cast<Bytef*>(compressed_data.data() + offset);
            stream_.avail_out = kZlibCompressionBufferSize;

            const int ret = deflate(&stream_, flush ? Z_FINISH : Z_NO_FLUSH);
            if (ret == Z_STREAM_ERROR) {
                throw std::runtime_error("zlib compression error");
            }
            offset += kZlibCompressionBufferSize  - stream_.avail_out;

            if (flush && ret == Z_STREAM_END) {
                break;
            }

        } while (stream_.avail_in > 0 || stream_.avail_out == 0);

        compressed_data.resize(offset);
    }

  private:
    z_stream stream_;
};

}  // namespace silkworm::rpc::http
