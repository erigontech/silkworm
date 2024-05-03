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

#include "snapshot_reader.hpp"

#include <stdexcept>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::snapshots {

Snapshot::Snapshot(
    SnapshotPath path,
    std::optional<MemoryMappedRegion> segment_region)
    : path_(std::move(path)),
      decoder_{path_.path(), segment_region} {}

Snapshot::~Snapshot() {
    close();
}

MemoryMappedRegion Snapshot::memory_file_region() const {
    const auto memory_file{decoder_.memory_file()};
    if (!memory_file) return MemoryMappedRegion{};
    return memory_file->region();
}

void Snapshot::reopen_segment() {
    close();

    // Open decompressor that opens the mapped file in turns
    decoder_.open();
}

Snapshot::Iterator& Snapshot::Iterator::operator++() {
    bool has_next = it_.has_next();
    ++it_;

    if (has_next) {
        deserializer_->decode_word(*it_);
        deserializer_->check_sanity_with_metadata(path_.block_from(), path_.block_to());
    } else {
        deserializer_.reset();
    }
    return *this;
}

bool operator==(const Snapshot::Iterator& lhs, const Snapshot::Iterator& rhs) {
    return (lhs.deserializer_ == rhs.deserializer_) &&
           (!lhs.deserializer_ || (lhs.it_ == rhs.it_));
}

Snapshot::Iterator Snapshot::begin(std::shared_ptr<SnapshotWordDeserializer> deserializer) const {
    auto it = decoder_.begin();
    if (it == decoder_.end()) {
        return end();
    }
    deserializer->decode_word(*it);
    deserializer->check_sanity_with_metadata(path_.block_from(), path_.block_to());
    return Snapshot::Iterator{std::move(it), std::move(deserializer), path()};
}

Snapshot::Iterator Snapshot::end() const {
    return Snapshot::Iterator{decoder_.end(), {}, path()};
}

seg::Decompressor::Iterator Snapshot::seek_decoder(uint64_t offset, std::optional<Hash> hash_prefix) const {
    return decoder_.seek(offset, hash_prefix ? ByteView{hash_prefix->bytes, 1} : ByteView{});
}

Snapshot::Iterator Snapshot::seek(uint64_t offset, std::optional<Hash> hash_prefix, std::shared_ptr<SnapshotWordDeserializer> deserializer) const {
    auto it = seek_decoder(offset, hash_prefix);
    if (it == decoder_.end()) {
        return end();
    }
    try {
        deserializer->decode_word(*it);
    } catch (...) {
        return end();
    }
    deserializer->check_sanity_with_metadata(path_.block_from(), path_.block_to());
    return Snapshot::Iterator{std::move(it), std::move(deserializer), path()};
}

void Snapshot::close() {
    // Close decompressor that closes the mapped file in turns
    decoder_.close();
}

}  // namespace silkworm::snapshots
