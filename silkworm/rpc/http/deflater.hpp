// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <libdeflate.h>

#include <memory>

namespace silkworm::rpc::http {

inline constexpr int kDefaultCompressionLevel = 6;

class Deflater {
  public:
    Deflater(const Deflater&) = delete;

    Deflater() {
        compressor_ = libdeflate_alloc_compressor(kDefaultCompressionLevel);
    }

    ~Deflater() {
        libdeflate_free_compressor(compressor_);
    }

    void compress(const std::string& clear_data, std::string& compressed_data) const {
        size_t max_compressed_data = libdeflate_gzip_compress_bound(compressor_, clear_data.size());
        compressed_data.resize(max_compressed_data);

        size_t compressed_data_size = libdeflate_gzip_compress(
            compressor_,
            clear_data.data(),
            clear_data.size(),
            compressed_data.data(),
            compressed_data.size());

        if (compressed_data_size == 0) {
            throw std::runtime_error("compression error");
        }
        compressed_data.resize(compressed_data_size);
    }

  private:
    struct libdeflate_compressor* compressor_;
};

}  // namespace silkworm::rpc::http
