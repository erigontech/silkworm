// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <utility>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::snapshots::seg {

class RawWordsStream {
  public:
    enum class OpenMode {
        kCreate,
        kOpen,
    };

    RawWordsStream(const std::filesystem::path& path, OpenMode open_mode, size_t buffer_size);
    explicit RawWordsStream(std::iostream& stream);

    void write_word(ByteView word, bool is_compressed = true);
    std::optional<std::pair<Bytes, bool>> read_word();

    void flush() { stream_.flush(); }
    void rewind() { stream_.seekg(0); }

  private:
    std::fstream file_;
    std::iostream& stream_;
    std::unique_ptr<char> stream_buffer_;
    Bytes encoded_length_;
};

}  // namespace silkworm::snapshots::seg
