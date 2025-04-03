// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
