// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
