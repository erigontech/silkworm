// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "btree_index.hpp"

#include <cstdlib>
#include <utility>

#include <gsl/util>

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

    btree_ = std::make_unique<BTree>(data_offsets_->size(), btree_fanout, encoded_nodes);
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
    if (ByteView{key}.compare(seek_key) >= 0) {
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

std::optional<BytesOrByteView> BTreeIndex::get(ByteView key, const KVSegmentReader& kv_segment) const {
    const KeyValueIndex index{kv_segment, data_offsets_, file_path_};
    return btree_->get(key, index);
}

std::optional<BTree::KeyValue> BTreeIndex::KeyValueIndex::lookup_key_value(DataIndex data_index) const {
    if (data_index >= data_offsets_->size()) {
        return std::nullopt;
    }
    const auto data_offset = data_offsets_->at(data_index);

    segment::KVSegmentReader<RawDecoder<BytesOrByteView>, RawDecoder<BytesOrByteView>> reader{kv_segment_};
    auto data_it = reader.seek(data_offset);
    if (data_it == reader.end()) {
        throw std::runtime_error{"key/value not found data_index=" + std::to_string(data_index) + " for " + file_path_.string()};
    }
    auto kv_pair = *data_it;

    return BTree::KeyValue{kv_pair.first, kv_pair.second};
}

std::optional<BytesOrByteView> BTreeIndex::KeyValueIndex::lookup_key(DataIndex data_index) const {
    if (data_index >= data_offsets_->size()) {
        return std::nullopt;
    }
    const auto data_offset = data_offsets_->at(data_index);

    segment::KVSegmentKeysReader<RawDecoder<BytesOrByteView>> reader{kv_segment_};
    const auto data_it = reader.seek(data_offset);
    if (data_it == reader.end()) {
        throw std::runtime_error{"key not found data_index=" + std::to_string(data_index) + " for " + file_path_.string()};
    }

    return *data_it;
}

std::optional<BTreeIndex::KeyValueIndex::LookupResult> BTreeIndex::KeyValueIndex::lookup_key_value(DataIndex data_index, ByteView k) const {
    if (data_index >= data_offsets_->size()) {
        return std::nullopt;
    }
    const auto data_offset = data_offsets_->at(data_index);

    const auto& decompressor = kv_segment_.decompressor();
    auto it = decompressor.seek(data_offset);
    if (it == decompressor.end() || !it.has_next()) {
        throw std::runtime_error{"key not found data_index=" + std::to_string(data_index) + " for " + file_path_.string()};
    }

    if (const int key_compare = ByteView{*it}.compare(k); key_compare != 0) {
        return LookupResult{key_compare, std::nullopt};
    }

    // Key matches: advance and read value
    ++it;
    return LookupResult{0, std::move(*it)};
}

static seg::Decompressor::Iterator kv_decompressor_seek_to_key(
    const seg::Decompressor& decompressor,
    uint64_t offset,
    ByteView search_key,
    size_t skip_max_count) {
    auto it = decompressor.seek(offset, {});
    if (it == decompressor.end()) {
        return it;
    }
    if (!it.has_next()) {
        return decompressor.end();
    }

    Decoder::Word key_word = std::move(*it);
    size_t skip_count{0};
    int cmp = 0;
    while ((cmp = ByteView{key_word}.compare(search_key)) < 0) {
        // Skip the value if key is still lower than the target one
        it.skip();
        if (++skip_count == skip_max_count) {
            return decompressor.end();
        }
        // Go to the next key w/ bound check
        ++it;
        if (!it.has_next()) {
            return decompressor.end();
        }
        key_word = std::move(*it);
    }
    if (cmp > 0) {  // Target key not found
        return decompressor.end();
    }
    return it;
}

std::optional<BytesOrByteView> BTreeIndex::KeyValueIndex::advance_key_value(const DataIndex data_index, const ByteView k, const size_t skip_max_count) const {
    if (data_index >= data_offsets_->size()) {
        return std::nullopt;
    }
    const auto data_offset = data_offsets_->at(data_index);

    const auto& decompressor = kv_segment_.decompressor();
    auto it = kv_decompressor_seek_to_key(decompressor, data_offset, k, skip_max_count);
    if ((it == decompressor.end()) || !it.has_next()) {
        return std::nullopt;
    }

    ++it;
    return std::move(*it);
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
    value_ = value_type{
        std::move(kv->first),
        std::move(kv->second),
    };
    return true;
}

}  // namespace silkworm::snapshots::btree
