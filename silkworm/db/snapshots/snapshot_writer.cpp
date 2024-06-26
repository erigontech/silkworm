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

#include "snapshot_writer.hpp"

namespace silkworm::snapshots {

SnapshotFileWriter::SnapshotFileWriter(
    SnapshotPath path,
    const std::filesystem::path& tmp_dir_path)
    : path_(std::move(path)),
      compressor_(path_.path(), tmp_dir_path) {
}

SnapshotFileWriter::Iterator& SnapshotFileWriter::Iterator::operator=(const SnapshotFileWriter::Iterator::value_type& value) {
    *it_ = value->encode_word();
    return *this;
}

SnapshotFileWriter::Iterator SnapshotFileWriter::out(std::shared_ptr<SnapshotWordSerializer> serializer) {
    return SnapshotFileWriter::Iterator{compressor_.add_word_iterator(), std::move(serializer)};
}

void SnapshotFileWriter::flush(SnapshotFileWriter writer) {
    seg::Compressor::compress(std::move(writer.compressor_));
}

}  // namespace silkworm::snapshots
