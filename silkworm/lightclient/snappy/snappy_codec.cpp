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

#include "snappy_codec.hpp"

#include <cstddef>
#include <string>

#include <snappy.h>

namespace silkworm::snappy {

//! Theoretically this method could use ::snappy::IsValidCompressedBuffer but doing so would produce
//! a valid result as of Snappy 1.1.9 for some invalid inputs [https://go.dev/play/p/nr86lSFGBKU]
//! So we fall back to a round-trip comparison to check validity (bad for performance).
bool is_valid_compressed_data(ByteView data) {
    Bytes uncompressed = decompress(data);
    Bytes compressed = compress(uncompressed);
    return compressed == data;
}

//! Apply Snappy block-format compression
std::string compress(std::string_view input) {
    std::string output;
    output.resize(::snappy::MaxCompressedLength(input.size()));

    size_t compressed_length;
    ::snappy::RawCompress(input.data(), input.size(), output.data(), &compressed_length);
    output.resize(compressed_length);

    return output;
}

//! Apply Snappy block-format decompression
std::string decompress(std::string_view input) {
    std::size_t uncompressed_length;
    bool ok = ::snappy::GetUncompressedLength(input.data(), input.size(), &uncompressed_length);
    if (!ok) {
        throw std::runtime_error("invalid snappy uncompressed length");
    }

    std::string output;
    output.resize(uncompressed_length);

    ok = ::snappy::RawUncompress(input.data(), input.size(), output.data());
    if (!ok) {
        throw std::runtime_error("invalid snappy data");
    }

    return output;
}

Bytes compress(ByteView data) {
    Bytes output;
    output.resize(::snappy::MaxCompressedLength(data.size()));

    size_t compressed_length;
    ::snappy::RawCompress(
        reinterpret_cast<const char*>(data.data()),
        data.size(),
        reinterpret_cast<char*>(output.data()),
        &compressed_length);
    output.resize(compressed_length);

    return output;
}

static size_t snappy_uncompressed_length(ByteView data) {
    size_t uncompressed_length;

    bool ok = ::snappy::GetUncompressedLength(
        reinterpret_cast<const char*>(data.data()),
        data.size(),
        &uncompressed_length);
    if (!ok) {
        throw std::runtime_error("invalid snappy uncompressed length");
    }

    return uncompressed_length;
}

Bytes decompress(ByteView data) {
    Bytes output;
    output.resize(snappy_uncompressed_length(data));

    bool ok = ::snappy::RawUncompress(
        reinterpret_cast<const char*>(data.data()),
        data.size(),
        reinterpret_cast<char*>(output.data()));
    if (!ok) {
        throw std::runtime_error("invalid snappy data");
    }

    return output;
}

}  // namespace silkworm::snappy
