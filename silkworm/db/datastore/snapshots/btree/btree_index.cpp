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

#include <cstdlib>
#include <utility>

#include <gsl/util>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/environment.hpp>

#include "../common/raw_codec.hpp"

namespace silkworm::snapshots::btree {

static bool is_btree_check_against_data_keys_enabled() {
    const auto btree_assert_offsets_var = Environment::get("BT_ASSERT_OFFSETS");
    return !btree_assert_offsets_var.empty() && (std::stoul(btree_assert_offsets_var) != 0);
}

BTreeIndex::BTreeIndex(
    std::filesystem::path index_file_path,
    std::optional<MemoryMappedRegion> index_region,
    uint64_t btree_fanout)
    : file_path_(std::move(index_file_path)) {
    // Gracefully handle the case of empty index file before memory mapping to avoid error
    if (std::filesystem::file_size(file_path_) == 0) {
        throw std::runtime_error("index " + file_path_.filename().string() + " is empty");
    }

    // Either use given memory-mapped region or create a new one
    memory_file_ = std::make_unique<MemoryMappedFile>(file_path_, index_region);
    SILKWORM_ASSERT(memory_file_->size() > 0);
    const auto memory_mapped_range = memory_file_->region();

    // Read encoded Elias-Fano 32-bit list of integers representing data offsets
    data_offsets_ = std::make_shared<EliasFanoList32>(EliasFanoList32::from_encoded_data(memory_mapped_range));
    ensure(data_offsets_->size() > 0, "BTreeIndex: invalid zero-length data offsets");

    const auto encoded_nodes = memory_mapped_range.subspan(data_offsets_->encoded_data_size());

    btree_ = std::make_unique<BTree>(
        data_offsets_->size(),
        btree_fanout,
        encoded_nodes);
}

void BTreeIndex::warmup_if_empty_or_check(const KVSegmentReader& kv_segment) {
    KeyValueIndex index{kv_segment, data_offsets_, file_path_};
    if (btree_->empty()) {
        btree_->warmup(index);
    } else if (is_btree_check_against_data_keys_enabled()) {
        btree_->check_against_data_keys(index);
    }
}

MemoryMappedRegion BTreeIndex::memory_file_region() const {
    return memory_file_->region();
}

std::optional<BTreeIndex::Cursor> BTreeIndex::seek(ByteView seek_key, const KVSegmentReader& kv_segment) const {
    KeyValueIndex index{kv_segment, data_offsets_, file_path_};
    auto [found, key, value, data_index] = btree_->seek(seek_key, index);
    if (key.compare(seek_key) >= 0) {
        return BTreeIndex::Cursor{
            this,
            std::move(key),
            std::move(value),
            data_index,
            &kv_segment,
        };
    }
    return std::nullopt;
}

std::optional<Bytes> BTreeIndex::get(ByteView key, const KVSegmentReader& kv_segment) const {
    KeyValueIndex index{kv_segment, data_offsets_, file_path_};
    auto result = btree_->get(key, index);
    if (!result) {
        return std::nullopt;
    }
    return std::move(result->value);
}

std::optional<BTree::KeyValue> BTreeIndex::KeyValueIndex::lookup_key_value(DataIndex data_index) const {
    if (data_index >= data_offsets_->size()) {
        return std::nullopt;
    }
    const auto data_offset = data_offsets_->at(data_index);

    segment::KVSegmentReader<RawDecoder<Bytes>, RawDecoder<Bytes>> reader{kv_segment_};
    auto data_it = reader.seek(data_offset);
    if (data_it == reader.end()) {
        throw std::runtime_error{"key/value not found data_index=" + std::to_string(data_index) + " for " + file_path_.string()};
    }
    auto kv_pair = *data_it;

    return BTree::KeyValue{std::move(kv_pair.first), std::move(kv_pair.second)};
}

std::optional<Bytes> BTreeIndex::KeyValueIndex::lookup_key(DataIndex data_index) const {
    if (data_index >= data_offsets_->size()) {
        return std::nullopt;
    }
    const auto data_offset = data_offsets_->at(data_index);

    segment::KVSegmentKeysReader<RawDecoder<Bytes>> reader{kv_segment_};
    auto data_it = reader.seek(data_offset);
    if (data_it == reader.end()) {
        throw std::runtime_error{"key not found data_index=" + std::to_string(data_index) + " for " + file_path_.string()};
    }
    Bytes key = std::move(*data_it);

    return key;
}

bool BTreeIndex::Cursor::next() {
    if (data_index_ + 1 >= index_->data_offsets_->size()) {
        return false;
    }
    ++data_index_;
    KeyValueIndex index{*kv_segment_, index_->data_offsets(), index_->path()};
    auto kv = index.lookup_key_value(data_index_);
    if (!kv) {
        return false;
    }
    key_ = std::move(kv->first);
    value_ = std::move(kv->second);
    return true;
}

}  // namespace silkworm::snapshots::btree
