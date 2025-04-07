// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <utility>
#include <vector>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::snapshots::seg {

class IntermediateCompressedStream {
  public:
    IntermediateCompressedStream(const std::filesystem::path& path, size_t buffer_size);
    explicit IntermediateCompressedStream(std::iostream& stream);

    struct CompressedWord {
        size_t raw_length{};
        std::vector<std::pair<size_t, size_t>> pattern_positions;

        friend bool operator==(const CompressedWord&, const CompressedWord&) = default;
    };

    void write_word(const CompressedWord& word);
    void write_uncovered_data(ByteView data);

    std::optional<CompressedWord> read_word();
    Bytes read_uncovered_data(size_t size);

    void flush() { stream_.flush(); }
    void rewind() { stream_.seekg(0); }

  private:
    void write_varint(size_t value);
    size_t read_varint();

    std::fstream file_;
    std::iostream& stream_;
    std::unique_ptr<char> stream_buffer_;
    Bytes encoded_buf_;
};

}  // namespace silkworm::snapshots::seg
