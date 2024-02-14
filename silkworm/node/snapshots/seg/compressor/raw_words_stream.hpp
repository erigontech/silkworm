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
    RawWordsStream(std::iostream& stream);

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
