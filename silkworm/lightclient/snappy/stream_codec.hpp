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

#include <algorithm>
#include <cstdio>
#include <string>

#include <boost/endian.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/detail/ios.hpp>
#include <boost/iostreams/operations.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/base.hpp>

namespace silkworm::snappy {

using namespace std::string_literals;

// Snappy is a compression/decompression library. It does not aim for maximum compression, or compatibility
// with any other compression library; instead, it aims for very high speeds and reasonable compression.
// Snappy can be used in one of two modes: block format and framing (a.k.a. stream) format

// Snappy framing format description: https://github.com/google/snappy/blob/main/framing_format.txt

constexpr std::size_t kChecksumSize{4};
constexpr std::size_t kChunkTypeSize{1};
constexpr std::size_t kChunkLengthSize{3};
constexpr std::size_t kChunkHeaderSize{kChunkTypeSize + kChunkLengthSize};

const std::string kMagicHeader{"\xff\x06\x00\x00"s};
const std::string kMagicBody{"sNaPpY"};
const std::string kMagicChunk{kMagicHeader + kMagicBody};

//! For the framing format: "the uncompressed data in a chunk must be no longer than 65536 bytes"
//! https://github.com/google/snappy/blob/master/framing_format.txt
constexpr std::streamsize kMaxBlockSize{65536};

//! kMaxEncodedLenOfMaxBlockSize equals MaxEncodedLen(kMaxBlockSize), but is hard-coded to be a const
constexpr std::size_t kMaxEncodedLenOfMaxBlockSize{76490};

const std::size_t kOutputBufferHeaderLength{kMagicChunk.size() + kChecksumSize + kChunkHeaderSize};
const std::size_t kOutputBufferLength{kOutputBufferHeaderLength + kMaxEncodedLenOfMaxBlockSize};

//! Section 4. Chunk types in https://github.com/google/snappy/blob/master/framing_format.txt
constexpr uint8_t kChunkTypeCompressedData   = 0x00;
constexpr uint8_t kChunkTypeUncompressedData = 0x01;
constexpr uint8_t kChunkTypePadding          = 0xfe;
constexpr uint8_t kChunkTypeStreamIdentifier = 0xff;

std::string framing_compress(std::string_view uncompressed);

std::string framing_uncompress(std::string_view compressed);

Bytes framing_compress(ByteView uncompressed);

Bytes framing_uncompress(ByteView compressed);

}  // namespace silkworm::snappy
