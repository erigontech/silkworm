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

Snapshot::Snapshot(SnapshotPath path, std::optional<MemoryMappedRegion> segment_region)
    : path_(std::move(path)), decoder_{path_.path(), segment_region} {}

MemoryMappedRegion Snapshot::memory_file_region() const {
    const auto memory_file{decoder_.memory_file()};
    if (!memory_file) return MemoryMappedRegion{};
    return memory_file->region();
}

void Snapshot::reopen_segment() {
    close_segment();

    // Open decompressor that opens the mapped file in turns
    decoder_.open();
}

Snapshot::Iterator& Snapshot::Iterator::operator++() {
    bool has_next = it_.has_next();
    ++it_;

    if (has_next) {
        serializer_->decode_word(*it_);
        serializer_->check_sanity_with_metadata(path_.block_from(), path_.block_to());
    } else {
        serializer_.reset();
    }
    return *this;
}

bool operator==(const Snapshot::Iterator& lhs, const Snapshot::Iterator& rhs) {
    return (lhs.serializer_ == rhs.serializer_) &&
           (!lhs.serializer_ || (lhs.it_ == rhs.it_));
}

Snapshot::Iterator Snapshot::begin(std::shared_ptr<SnapshotWordSerializer> serializer) const {
    auto it = decoder_.begin();
    if (it == decoder_.end()) {
        return end();
    }
    serializer->decode_word(*it);
    serializer->check_sanity_with_metadata(path_.block_from(), path_.block_to());
    return Snapshot::Iterator{std::move(it), std::move(serializer), path()};
}

Snapshot::Iterator Snapshot::end() const {
    return Snapshot::Iterator{decoder_.end(), {}, path()};
}

std::optional<Snapshot::WordItem> Snapshot::next_item(uint64_t offset, ByteView prefix) const {
    SILK_TRACE << "Snapshot::next_item offset: " << offset;
    auto data_iterator = decoder_.make_iterator();
    data_iterator.reset(offset);

    std::optional<WordItem> item;
    if (!data_iterator.has_next()) {
        return item;
    }
    if (!prefix.empty() && !data_iterator.has_prefix(prefix)) {
        return item;
    }

    item = WordItem{};
    try {
        item->offset = data_iterator.next(item->value);
    } catch (const std::runtime_error& re) {
        SILK_WARN << "Snapshot::next_item invalid offset: " << offset << " what: " << re.what();
        return {};
    }

    return item;
}

void Snapshot::close() {
    close_segment();
    close_index();
}

void Snapshot::close_segment() {
    // Close decompressor that closes the mapped file in turns
    decoder_.close();
}

}  // namespace silkworm::snapshots
