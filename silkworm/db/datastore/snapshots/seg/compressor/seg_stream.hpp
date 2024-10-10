/*
   Copyright 2024 The Silkworm Authors

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

#include <filesystem>
#include <fstream>
#include <ostream>
#include <vector>

#include <silkworm/core/common/bytes.hpp>

#include "bit_stream.hpp"

namespace silkworm::snapshots::seg {

class SegStream {
  public:
    explicit SegStream(const std::filesystem::path& path);
    explicit SegStream(std::ostream& stream);

    template <typename TData>
    struct HuffmanCodeTableSymbol {
        size_t code_bits{};
        TData data{};
    };

    template <typename TData>
    using HuffmanCodeTable = std::vector<HuffmanCodeTableSymbol<TData>>;

    struct Header {
        size_t words_count{};
        size_t empty_words_count{};
        HuffmanCodeTable<ByteView> patterns;
        HuffmanCodeTable<size_t> positions;
    };

    void write_header(const Header& header);

    BitStream& codes() { return bit_stream_; }

    void write_uncovered_data(ByteView data);

  private:
    void write_big_endian(size_t value);
    void write_varint(size_t value);

    Bytes encoded_buf_;
    std::ofstream file_;
    std::ostream& stream_;
    BitStream bit_stream_;
};

}  // namespace silkworm::snapshots::seg
