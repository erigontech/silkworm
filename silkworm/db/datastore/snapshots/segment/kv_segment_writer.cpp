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

#include "kv_segment_writer.hpp"

namespace silkworm::snapshots::segment {

KVSegmentFileWriter::KVSegmentFileWriter(
    SnapshotPath path,
    seg::CompressionKind compression_kind,
    const std::filesystem::path& tmp_dir_path)
    : path_{std::move(path)},
      compressor_{path_.path(), tmp_dir_path, compression_kind} {
}

KVSegmentFileWriter::Iterator& KVSegmentFileWriter::Iterator::operator=(
    const KVSegmentFileWriter::Iterator::value_type& value) {
    *it_++ = value.first->encode_word();
    *it_++ = value.second->encode_word();
    return *this;
}

KVSegmentFileWriter::Iterator KVSegmentFileWriter::out(
    std::shared_ptr<Encoder> key_encoder,
    std::shared_ptr<Encoder> value_encoder) {
    return KVSegmentFileWriter::Iterator{
        compressor_.add_word_iterator(),
        std::move(key_encoder),
        std::move(value_encoder),
    };
}

void KVSegmentFileWriter::flush(KVSegmentFileWriter writer) {
    seg::Compressor::compress(std::move(writer.compressor_));
}

}  // namespace silkworm::snapshots::segment
