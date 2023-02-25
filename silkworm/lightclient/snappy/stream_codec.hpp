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

#include <iostream>

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

/*
Each encoded block begins with the varint-encoded length of the decoded data,
followed by a sequence of chunks. Chunks begin and end on byte boundaries. The
first byte of each chunk is broken into its 2 least and 6 most significant bits
called l and m: l ranges in [0, 4) and m ranges in [0, 64). l is the chunk tag.
Zero means a literal tag. All other values mean a copy tag.

For literal tags:
  - If m < 60, the next 1 + m bytes are literal bytes.
  - Otherwise, let n be the little-endian unsigned integer denoted by the next
    m - 59 bytes. The next 1 + n bytes after that are literal bytes.

For copy tags, length bytes are copied from offset bytes ago, in the style of
Lempel-Ziv compression algorithms. In particular:
  - For l == 1, the offset ranges in [0, 1<<11) and the length in [4, 12).
    The length is 4 + the low 3 bits of m. The high 3 bits of m form bits 8-10
    of the offset. The next byte is bits 0-7 of the offset.
  - For l == 2, the offset ranges in [0, 1<<16) and the length in [1, 65).
    The length is 1 + m. The offset is the little-endian unsigned integer
    denoted by the next 2 bytes.
  - For l == 3, this tag is a legacy format that is no longer issued by most
    encoders. Nonetheless, the offset ranges in [0, 1<<32) and the length in
    [1, 65). The length is 1 + m. The offset is the little-endian unsigned
    integer denoted by the next 4 bytes.
*/

using namespace std::string_literals;

constexpr std::size_t kChecksumSize{4};
constexpr std::size_t kChunkHeaderSize{4};

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

constexpr uint8_t kChunkTypeCompressedData   = 0x00;
constexpr uint8_t kChunkTypeUncompressedData = 0x01;
constexpr uint8_t kChunkTypePadding          = 0xfe;
constexpr uint8_t kChunkTypeStreamIdentifier = 0xff;

std::string framing_compress(std::string_view uncompressed);

std::string framing_uncompress(std::string_view compressed);

Bytes framing_compress(ByteView uncompressed);

Bytes framing_uncompress(ByteView compressed);

}  // namespace silkworm::snappy
