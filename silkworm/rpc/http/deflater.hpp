/*
   Copyright 2023 The Silkworm Authors

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
