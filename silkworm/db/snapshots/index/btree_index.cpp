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

#include "btree_index.hpp"

#include <utility>

#include <gsl/util>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/ensure.hpp>

namespace silkworm::snapshots::index {

BTreeIndex::BTreeIndex(seg::Decompressor& kv_decompressor,
                       std::filesystem::path index_file_path,
                       std::optional<MemoryMappedRegion> index_region,
                       uint64_t btree_fanout)
    : file_path_(std::move(index_file_path)) {
    ensure(kv_decompressor.is_open(), "BTreeIndex: KV file decompressor must be opened");

    // Gracefully handle the case of empty index file before memory mapping to avoid error
    if (std::filesystem::file_size(file_path_) == 0) {
        return;
    }

    // Either use given memory-mapped region or create a new one
    memory_file_ = std::make_unique<MemoryMappedFile>(file_path_, index_region);
    SILKWORM_ASSERT(memory_file_->size() > 0);
    const auto memory_mapped_range = memory_file_->region();

    // Read encoded Elias-Fano 32-bit list of integers representing data offsets
    data_offsets_ = EliasFanoList32::from_encoded_data(memory_mapped_range);
    ensure(data_offsets_->sequence_length() > 0, "BTreeIndex: invalid zero-length data offsets");

    const auto encoded_nodes = memory_mapped_range.subspan(data_offsets_->encoded_data_size());

    // Let the OS know we're going to read data sequentially now, then restore normal (i.e. unknown) reading behavior
    kv_decompressor.advise_sequential();
    [[maybe_unused]] auto _ = gsl::finally([&]() { kv_decompressor.advise_normal(); });
    auto kv_it = kv_decompressor.begin();

    btree_ = std::make_unique<BTree>(
        data_offsets_->sequence_length(),
        btree_fanout,
        [this](auto data_index, auto& data_it) { return lookup_data(data_index, data_it); },
        [this](auto key, auto data_index, auto& data_it) { return compare_key(key, data_index, data_it); },
        kv_it,
        encoded_nodes);
}

BTreeIndex::Cursor::Cursor(BTreeIndex* index, ByteView key, ByteView value, DataIndex data_index, DataIterator data_it)
    : index_(index), key_(key), value_(value), data_index_(data_index), data_it_(std::move(data_it)) {}

std::optional<BTreeIndex::Cursor> BTreeIndex::seek(ByteView seek_key, DataIterator data_it) {
    const auto [found, key, value, data_index] = btree_->seek(seek_key, data_it);
    if (key.compare(seek_key) >= 0) {
        return new_cursor(key, value, data_index, data_it);
    }
    return std::nullopt;
}

std::optional<Bytes> BTreeIndex::get(ByteView key, DataIterator data_it) {
    if (empty()) {
        return std::nullopt;
    }
    const auto [key_found, _, data_index] = btree_->get(key, data_it);
    if (!key_found) {
        return std::nullopt;
    }
    const auto [kv_found, kv] = lookup_data(data_index, data_it);
    if (!kv_found) {
        return std::nullopt;
    }
    return kv.second;
}

BTree::LookupResult BTreeIndex::lookup_data(DataIndex data_index, DataIterator data_it) {
    if (data_index >= data_offsets_->sequence_length()) {
        return {/*found=*/false, {}};
    }

    const auto data_offset = data_offsets_->get(data_index);
    data_it.reset(data_offset);
    if (!data_it.has_next()) {
        throw std::runtime_error{"key not found data_index=" + std::to_string(data_index) + " for " + file_path_.string()};
    }
    Bytes key;
    data_it.next(key);
    if (!data_it.has_next()) {
        throw std::runtime_error{"value not found data_index=" + std::to_string(data_index) + " for " + file_path_.string()};
    }
    Bytes value;
    data_it.next(value);
    return {/*found=*/true, {key, value}};
}

BTree::CompareResult BTreeIndex::compare_key(ByteView key, DataIndex data_index, DataIterator data_it) {
    ensure(data_index < data_offsets_->sequence_length(),
           [&]() { return "out-of-bounds data_index=" + std::to_string(data_index) + " key=" + to_hex(key); });

    const auto data_offset = data_offsets_->get(data_index);
    data_it.reset(data_offset);
    if (!data_it.has_next()) {
        throw std::runtime_error{"key not found data_index=" + std::to_string(data_index) + " for " + file_path_.string()};
    }
    Bytes data_key;
    data_it.next(data_key);
    return {data_key.compare(key), data_key};
}

BTreeIndex::Cursor BTreeIndex::new_cursor(ByteView key, ByteView value, DataIndex data_index, DataIterator data_it) {
    return BTreeIndex::Cursor{this, key, value, data_index, std::move(data_it)};
}

bool BTreeIndex::Cursor::next() {
    if (!to_next()) {
        return false;
    }
    const auto [found, kv] = index_->lookup_data(data_index_, data_it_);
    if (!found) {
        return false;
    }
    key_ = kv.first;
    value_ = kv.second;
    return true;
}

bool BTreeIndex::Cursor::to_next() {
    if (data_index_ + 1 == index_->data_offsets_->sequence_length()) {
        return false;
    }
    ++data_index_;
    return true;
}

}  // namespace silkworm::snapshots::index
