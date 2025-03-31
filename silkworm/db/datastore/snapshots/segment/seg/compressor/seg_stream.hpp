// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
