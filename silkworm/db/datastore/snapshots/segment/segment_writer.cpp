// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "segment_writer.hpp"

namespace silkworm::snapshots::segment {

SegmentFileWriter::SegmentFileWriter(
    SnapshotPath path,
    const std::filesystem::path& tmp_dir_path,
    bool is_compressed)
    : path_{std::move(path)},
      compressor_{
          path_.path(),
          tmp_dir_path,
          is_compressed ? seg::CompressionKind::kAll : seg::CompressionKind::kNone,
      } {}

SegmentFileWriter::Iterator& SegmentFileWriter::Iterator::operator=(const SegmentFileWriter::Iterator::value_type& value) {
    *it_ = value->encode_word();
    return *this;
}

SegmentFileWriter::Iterator SegmentFileWriter::out(std::shared_ptr<Encoder> encoder) {
    return SegmentFileWriter::Iterator{compressor_.add_word_iterator(), std::move(encoder)};
}

void SegmentFileWriter::flush(SegmentFileWriter writer) {
    seg::Compressor::compress(std::move(writer.compressor_));
}

}  // namespace silkworm::snapshots::segment
