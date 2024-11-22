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

#include "seg_zip.hpp"

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/common/directories.hpp>

#include "compressor.hpp"
#include "compressor/raw_words_stream.hpp"
#include "decompressor.hpp"

namespace silkworm::snapshots::seg {

void seg_zip(const std::filesystem::path& path) {
    RawWordsStream words{path, RawWordsStream::OpenMode::kOpen, 1_Mebi};

    auto out_path = path;
    out_path.replace_extension("seg");
    TemporaryDirectory tmp_dir;
    Compressor compressor{out_path, tmp_dir.path()};

    while (auto word = words.read_word()) {
        compressor.add_word(word->first, word->second);
    }

    Compressor::compress(std::move(compressor));
}

void seg_unzip(const std::filesystem::path& path) {
    Decompressor decompressor{path};

    auto out_path = path;
    out_path.replace_extension("idt");
    RawWordsStream words{out_path, RawWordsStream::OpenMode::kCreate, 1_Mebi};

    for (auto& word : decompressor) {
        words.write_word(word);
    }
}

}  // namespace silkworm::snapshots::seg
