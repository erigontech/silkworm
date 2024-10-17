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
#include <iterator>
#include <memory>

#include <silkworm/core/common/bytes.hpp>

#include "compression_kind.hpp"

namespace silkworm::snapshots::seg {

class CompressorImpl;

class Compressor {
  public:
    Compressor(
        const std::filesystem::path& path,
        const std::filesystem::path& tmp_dir_path,
        CompressionKind compression_kind = CompressionKind::kAll);
    ~Compressor();

    Compressor(Compressor&& other) noexcept;
    Compressor& operator=(Compressor&& other) noexcept;

    void add_word(ByteView word);
    void add_word(ByteView word, bool is_compressed);
    static void compress(Compressor compressor);

    using value_type = ByteView;
    using Iterator = std::back_insert_iterator<Compressor>;
    void push_back(ByteView word) { add_word(word); }
    Iterator add_word_iterator() {
        return std::back_inserter(*this);
    }

  private:
    std::unique_ptr<CompressorImpl> p_impl_;
};

}  // namespace silkworm::snapshots::seg
