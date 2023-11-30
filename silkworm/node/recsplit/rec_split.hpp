/*
   Copyright 2022 The Silkworm Authors

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

/*
 * Sux: Succinct data structures
 *
 * Copyright (C) 2019-2020 Emmanuel Esposito and Sebastiano Vigna
 *
 *  This library is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public License as published by the Free
 *  Software Foundation; either version 3 of the License, or (at your option)
 *  any later version.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * Under Section 7 of GPL version 3, you are granted additional permissions
 * described in the GCC Runtime Library Exception, version 3.1, as published by
 * the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License and a copy of
 * the GCC Runtime Library Exception along with this program; see the files
 * COPYING3 and COPYING.RUNTIME respectively.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <array>
#include <bit>
#include <cassert>
#include <chrono>
#include <cmath>
#include <fstream>
#include <limits>
#include <memory>
#include <numbers>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <gsl/narrow>
#include <gsl/util>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/memory_mapped_file.hpp>
#include <silkworm/node/etl/collector.hpp>
#include <silkworm/node/recsplit/encoding/elias_fano.hpp>
#include <silkworm/node/recsplit/encoding/golomb_rice.hpp>
#include <silkworm/node/recsplit/support/murmur_hash3.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"

namespace silkworm::succinct {

using namespace std::chrono;

//! Assumed *maximum* size of a bucket. Works with high probability up to average bucket size ~2000
static const int kMaxBucketSize = 3000;

//! Assumed *maximum* size of splitting tree leaves
static const int kMaxLeafSize = 24;

//! Assumed *maximum* size of splitting tree fanout
static const int kMaxFanout = 32;

//! Starting seed at given distance from the root (extracted at random)
static constexpr std::array<uint64_t, 20> kStartSeed = {
    0x106393c187cae21a, 0x6453cec3f7376937, 0x643e521ddbd2be98, 0x3740c6412f6572cb, 0x717d47562f1ce470, 0x4cd6eb4c63befb7c, 0x9bfd8c5e18c8da73,
    0x082f20e10092a9a3, 0x2ada2ce68d21defc, 0xe33cb4f3e7c6466b, 0x3980be458c509c59, 0xc466fd9584828e8c, 0x45f0aabe1a61ede6, 0xf6e7b8b33ad9b98d,
    0x4ef95e25f4b4983d, 0x81175195173b92d3, 0x4e50927d8dd15978, 0x1ea2099d1fafae7f, 0x425c8a06fbaaa815, 0xcd4216006c74052a};

//! David Stafford's (http://zimbry.blogspot.com/2011/09/better-bit-mixingsuccinct::-improving-on.html)
//! 13th variant of the 64-bit finalizer function in Austin Appleby's MurmurHash3 (https://github.com/aappleby/smhasher)
//! @param z a 64-bit integer
//! @return a 64-bit integer obtained by mixing the bits of `z`
uint64_t inline remix(uint64_t z) {
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

//! 128-bit hash used in the construction of RecSplit (first of all keys are hashed using MurmurHash3)
//! Moreover, it is possible to build and query RecSplit instances using 128-bit random hashes (mainly for test purposes)
struct hash128_t {
    uint64_t first;   // The high 64-bit hash half
    uint64_t second;  // The low 64-bit hash half

    bool operator<(const hash128_t& o) const { return first < o.first || second < o.second; }
};

// Quick replacements for min/max on not-so-large integers
static constexpr inline uint64_t min(int64_t x, int64_t y) { return static_cast<uint64_t>(y + ((x - y) & ((x - y) >> 63))); }
static constexpr inline uint64_t max(int64_t x, int64_t y) { return static_cast<uint64_t>(x - ((x - y) & ((x - y) >> 63))); }

// Optimal Golomb-Rice parameters for leaves
static constexpr uint8_t bij_memo[] = {0, 0, 0, 1, 3, 4, 5, 7, 8, 10, 11, 12, 14, 15, 16, 18, 19, 21, 22, 23, 25, 26, 28, 29, 30};

//! The splitting strategy of Recsplit algorithm is embedded into the generation code, which uses only the public fields
//! SplittingStrategy::lower_aggr and SplittingStrategy::upper_aggr.
template <std::size_t LEAF_SIZE>
class SplittingStrategy {
    static_assert(1 <= LEAF_SIZE && LEAF_SIZE <= kMaxLeafSize);

  public:
    //! The lower bound for primary (lower) key aggregation
    static constexpr std::size_t kLowerAggregationBound = LEAF_SIZE * max(2,
                                                                          // NOLINTNEXTLINE(bugprone-incorrect-roundings)
                                                                          static_cast<int64_t>(0.35 * LEAF_SIZE + 0.5));

    //! The lower bound for secondary (upper) key aggregation
    static constexpr std::size_t kUpperAggregationBound = kLowerAggregationBound *
                                                          (LEAF_SIZE < 7 ? 2 : static_cast<int64_t>(0.21 * LEAF_SIZE + 0.9));

    static inline std::pair<std::size_t, std::size_t> split_params(const std::size_t m) {
        std::size_t fanout{0}, unit{0};
        if (m > kUpperAggregationBound) {  // High-level aggregation (fanout 2)
            unit = kUpperAggregationBound * (uint16_t((m + 1) / 2 + kUpperAggregationBound - 1) / kUpperAggregationBound);
            fanout = 2;
        } else if (m > kLowerAggregationBound) {  // Second-level aggregation
            unit = kLowerAggregationBound;
            fanout = uint16_t(m + kLowerAggregationBound - 1) / kLowerAggregationBound;
        } else {  // First-level aggregation
            unit = LEAF_SIZE;
            fanout = uint16_t(m + LEAF_SIZE - 1) / LEAF_SIZE;
        }
        return {fanout, unit};
    }
};

//! Size in bytes of 1st fixed metadata header fields in RecSplit-encoded file
static constexpr std::size_t kBaseDataIdLength{sizeof(uint64_t)};
static constexpr std::size_t kKeyCountLength{sizeof(uint64_t)};
static constexpr std::size_t kBytesPerRecordLength{sizeof(uint8_t)};

//! Size in bytes of 1st fixed metadata header in RecSplit-encoded file
constexpr std::size_t kFirstMetadataHeaderLength{
    kBaseDataIdLength + kKeyCountLength + kBytesPerRecordLength};

//! Size in bytes of 2nd fixed metadata header fields in RecSplit-encoded file
static constexpr std::size_t kBucketCountLength{sizeof(uint64_t)};
static constexpr std::size_t kBucketSizeLength{sizeof(uint16_t)};
static constexpr std::size_t kLeafSizeLength{sizeof(uint16_t)};
static constexpr std::size_t kSaltSizeLength{sizeof(uint32_t)};
static constexpr std::size_t kStartSeedSizeLength{sizeof(uint8_t)};

static constexpr std::size_t kDoubleIndexFlagLength{sizeof(uint8_t)};
static constexpr std::size_t kGolombParamSizeLength{sizeof(uint32_t)};  // Erigon writes 4-instead-of-2 bytes
static constexpr std::size_t kEliasFano32CountLength{sizeof(uint64_t)};
static constexpr std::size_t kEliasFano32ULength{sizeof(uint64_t)};

//! Size in bytes of 2nd fixed metadata header in RecSplit-encoded file
constexpr std::size_t kSecondMetadataHeaderLength{
    kBucketCountLength + kBucketSizeLength + kLeafSizeLength + kSaltSizeLength + kStartSeedSizeLength};

//! Parameters for modified Recursive splitting (RecSplit) algorithm.
struct RecSplitSettings {
    std::size_t keys_count;            // The total number of keys in the RecSplit
    uint16_t bucket_size;              // The number of keys in each bucket (except probably last one)
    std::filesystem::path index_path;  // The path of the generated RecSplit index file
    uint64_t base_data_id;             // Application-specific base data ID written in index header
    bool double_enum_index{true};      // Flag indicating if 2-level index is required
};

//! Recursive splitting (RecSplit) is an efficient algorithm to identify minimal perfect hash functions.
//! The template parameter LEAF_SIZE decides how large a leaf will be. Larger leaves imply slower construction, but less
//! space and faster evaluation
//! @tparam LEAF_SIZE the size of a leaf, typical value range from 6 to 8 for fast small maps or up to 16 for very compact functions
template <std::size_t LEAF_SIZE>
class RecSplit {
  public:
    using SplitStrategy = SplittingStrategy<LEAF_SIZE>;
    using GolombRiceBuilder = typename GolombRiceVector::Builder;
    using EliasFano = EliasFanoList32;
    using DoubleEliasFano = DoubleEliasFanoList16;

    //! The base class for RecSplit building strategies
    struct BuildingStrategy {
        virtual void init(std::size_t bucket_size, std::size_t bucket_count, std::size_t key_count, bool double_enum_index) = 0;
        virtual ~BuildingStrategy() = default;

        virtual void add_key(uint64_t bucket_id, uint64_t bucket_key, uint64_t offset) = 0;
        virtual bool build_mph_index(std::ofstream& index_output_stream, GolombRiceVector& golomb_rice_codes,
                                     uint16_t& golomb_param_max_index, DoubleEliasFano& double_ef_index, uint8_t bytes_per_record) = 0;
        virtual void build_enum_index(std::unique_ptr<EliasFano>& ef_offsets) = 0;
        virtual void clear() = 0;

        virtual uint64_t keys_added() = 0;
        virtual uint64_t max_offset() = 0;
    };

    struct SequentialBuildingStrategy;
    struct ParallelBuildingStrategy;

    explicit RecSplit(const RecSplitSettings& settings, std::unique_ptr<BuildingStrategy> bs, uint32_t salt = 0)
        : bucket_size_(settings.bucket_size),
          key_count_(settings.keys_count),
          bucket_count_((key_count_ + bucket_size_ - 1) / bucket_size_),
          base_data_id_(settings.base_data_id),
          index_path_(settings.index_path),
          double_enum_index_(settings.double_enum_index),
          building_strategy_(std::move(bs)) {
        building_strategy_->init(bucket_size_, bucket_count_, key_count_, double_enum_index_);

        // Generate random salt for murmur3 hash
        std::random_device rand_dev;
        std::mt19937 rand_gen32{rand_dev()};
        salt_ = salt != 0 ? salt : static_cast<uint32_t>(rand_gen32());
        hasher_ = std::make_unique<Murmur3>(salt_);
    }

    explicit RecSplit(std::filesystem::path index_path, std::optional<MemoryMappedRegion> index_region = {})
        : index_path_{index_path},
          encoded_file_{std::make_optional<MemoryMappedFile>(std::move(index_path), index_region)} {
        SILK_TRACE << "RecSplit encoded file path: " << encoded_file_->path();
        check_minimum_length(kFirstMetadataHeaderLength);

        const auto address = encoded_file_->address();

        encoded_file_->advise_sequential();

        // Read fixed metadata header fields from RecSplit-encoded file
        base_data_id_ = endian::load_big_u64(address);
        key_count_ = endian::load_big_u64(address + kBaseDataIdLength);
        bytes_per_record_ = address[kBaseDataIdLength + kKeyCountLength];
        record_mask_ = (uint64_t{1} << (8 * bytes_per_record_)) - 1;
        SILK_TRACE << "Base data ID: " << base_data_id_ << " key count: " << key_count_
                   << " bytes per record: " << bytes_per_record_ << " record mask: " << record_mask_;

        // Compute offset for variable metadata header fields
        uint64_t offset = kFirstMetadataHeaderLength + key_count_ * bytes_per_record_;
        check_minimum_length(offset + kSecondMetadataHeaderLength);

        // Read offset-based metadata fields
        bucket_count_ = endian::load_big_u64(address + offset);
        offset += kBucketCountLength;
        bucket_size_ = endian::load_big_u16(address + offset);
        offset += kBucketSizeLength;
        const uint16_t leaf_size = endian::load_big_u16(address + offset);
        SILKWORM_ASSERT(leaf_size == LEAF_SIZE);
        offset += kLeafSizeLength;

        // Read salt
        salt_ = endian::load_big_u32(address + offset);
        offset += kSaltSizeLength;
        hasher_ = std::make_unique<Murmur3>(salt_);

        // Read start seed
        const uint8_t start_seed_length = (address + offset)[0];
        offset += kStartSeedSizeLength;
        SILKWORM_ASSERT(start_seed_length == kStartSeed.size());
        check_minimum_length(offset + start_seed_length * sizeof(uint64_t));
        std::array<uint64_t, kStartSeed.size()> start_seed{};
        for (std::size_t i{0}; i < start_seed_length; ++i) {
            start_seed[i] = endian::load_big_u64(address + offset);
            offset += sizeof(uint64_t);
        }
        SILKWORM_ASSERT(start_seed == kStartSeed);

        // Read double-index flag
        check_minimum_length(offset + kDoubleIndexFlagLength);
        double_enum_index_ = (address + offset)[0] != 0;
        offset += kDoubleIndexFlagLength;

        if (double_enum_index_) {
            check_minimum_length(offset + kEliasFano32CountLength + kEliasFano32ULength);

            // Read Elias-Fano index for offsets
            const uint64_t count = endian::load_big_u64(address + offset);
            offset += kEliasFano32CountLength;
            const uint64_t u = endian::load_big_u64(address + offset);
            offset += kEliasFano32ULength;
            std::span<uint8_t> remaining_data{address + offset, encoded_file_->length() - offset};
            ef_offsets_ = std::make_unique<EliasFano>(count, u, remaining_data);
            offset += ef_offsets_->data().size() * sizeof(uint64_t);
        }

        // Read the number of Golomb-Rice code params
        check_minimum_length(offset + kGolombParamSizeLength);
        const uint16_t golomb_param_size = endian::load_big_u16(address + offset);
        golomb_param_max_index_ = golomb_param_size - 1;
        offset += kGolombParamSizeLength;

        MemoryMappedInputStream mmis{address + offset, encoded_file_->length() - offset};

        // Read Golomb-Rice codes
        mmis >> golomb_rice_codes_;
        offset += sizeof(uint64_t) + golomb_rice_codes_.size() * sizeof(uint64_t);

        // Read double Elias-Fano code for bucket cumulative keys and bit positions
        mmis >> double_ef_index_;
        offset += 5 * sizeof(uint64_t) + double_ef_index_.data().size() * sizeof(uint64_t);

        SILKWORM_ASSERT(offset == encoded_file_->length());

        encoded_file_->advise_random();

        // Prevent any new key addition
        built_ = true;
    }

    void add_key(const hash128_t& key_hash, uint64_t offset) {
        if (built_) {
            throw std::logic_error{"cannot add key after perfect hash function has been built"};
        }

        uint64_t bucket_id = hash128_to_bucket(key_hash);
        auto bucket_key = key_hash.second;

        building_strategy_->add_key(bucket_id, bucket_key, offset);
    }

    void add_key(const void* key_data, const size_t key_length, uint64_t offset) {
        if (built_) {
            throw std::logic_error{"cannot add key after perfect hash function has been built"};
        }

        const auto key_hash = murmur_hash_3(key_data, key_length);
        add_key(key_hash, offset);
    }

    void add_key(const std::string& key, uint64_t offset) {
        add_key(key.c_str(), key.size(), offset);
    }

    //! Build the MPHF using the RecSplit algorithm and save the resulting index file
    //! \warning duplicate keys will cause this method to never return
    [[nodiscard]] bool build() {
        if (built_) {
            throw std::logic_error{"perfect hash function already built"};
        }

        if (building_strategy_->keys_added() != key_count_) {
            throw std::logic_error{"keys expected: " + std::to_string(key_count_) +
                                   " added: " + std::to_string(building_strategy_->keys_added())};
        }
        const auto tmp_index_path{std::filesystem::path{index_path_}.concat(".tmp")};
        std::ofstream index_output_stream{tmp_index_path, std::ios::binary};
        SILK_TRACE << "[index] creating temporary index file: " << tmp_index_path.string();

        // Write minimal app-specific data ID in the index file
        Bytes uint64_buffer(8, '\0');
        endian::store_big_u64(uint64_buffer.data(), base_data_id_);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
        SILK_TRACE << "[index] written base data ID: " << base_data_id_;

        // Write number of keys
        endian::store_big_u64(uint64_buffer.data(), building_strategy_->keys_added());
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
        SILK_TRACE << "[index] written number of keys: " << building_strategy_->keys_added();

        // Write number of bytes per index record
        bytes_per_record_ = (std::bit_width(building_strategy_->max_offset()) + 7) / 8;
        index_output_stream.write(reinterpret_cast<const char*>(&bytes_per_record_), sizeof(uint8_t));
        SILK_TRACE << "[index] written bytes per record: " << int(bytes_per_record_);

        SILK_TRACE << "[index] calculating file=" << index_path_.string();

        // Calc Minimal Perfect Hashes using recsplit algorithm
        // & write table: mph-output -> ordinal
        bool collision = building_strategy_->build_mph_index(index_output_stream, golomb_rice_codes_, golomb_param_max_index_,
                                                             double_ef_index_, bytes_per_record_);
        if (collision) return true;

        // Compute table: ordinal -> offset
        if (double_enum_index_) {
            building_strategy_->build_enum_index(ef_offsets_);
        }

        built_ = true;

        // SILK_INFO << "written bytes so far " << index_output_stream.tellp();

        // Write out bucket count, bucket size, leaf size
        endian::store_big_u64(uint64_buffer.data(), bucket_count_);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
        SILK_TRACE << "[index] written bucket count: " << bucket_count_;

        endian::store_big_u16(uint64_buffer.data(), bucket_size_);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint16_t));
        SILK_TRACE << "[index] written bucket size: " << bucket_size_;

        endian::store_big_u16(uint64_buffer.data(), LEAF_SIZE);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint16_t));
        SILK_TRACE << "[index] written leaf size: " << LEAF_SIZE;

        // Write out salt
        endian::store_big_u32(uint64_buffer.data(), salt_);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint32_t));
        SILK_TRACE << "[index] written murmur3 salt: " << salt_ << " [" << to_hex(uint64_buffer) << "]";

        // Write out start seeds
        constexpr uint8_t start_seed_length = kStartSeed.size();
        index_output_stream.write(reinterpret_cast<const char*>(&start_seed_length), sizeof(uint8_t));
        SILK_TRACE << "[index] written start seed length: " << int(start_seed_length);

        for (const uint64_t s : kStartSeed) {
            endian::store_big_u64(uint64_buffer.data(), s);
            index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
        }
        SILK_TRACE << "[index] written start seed: first=" << kStartSeed[0] << " last=" << kStartSeed[kStartSeed.size() - 1];

        // Write out index flag
        const uint8_t enum_index_flag = double_enum_index_ ? 1 : 0;
        index_output_stream.write(reinterpret_cast<const char*>(&enum_index_flag), sizeof(uint8_t));

        // Write out Elias-Fano code for offsets (if any)
        if (double_enum_index_) {
            index_output_stream << *ef_offsets_;
            SILK_TRACE << "[index] written EF code for offsets [size: " << ef_offsets_->count() - 1 << "]";
        }

        // Write out the number of Golomb-Rice codes used i.e. the max index used plus one
        endian::store_big_u16(uint64_buffer.data(), golomb_param_max_index_ + 1);
        // Erigon writes 4-instead-of-2 bytes here: 2 spurious come from previous buffer content, i.e. last seed value
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint32_t));
        SILK_TRACE << "[index] written GR params count: " << golomb_param_max_index_ + 1 << " code size: " << golomb_rice_codes_.size();

        // Write out Golomb-Rice code
        index_output_stream << golomb_rice_codes_;

        // Write out Elias-Fano code for bucket cumulative keys and bit positions
        index_output_stream << double_ef_index_;

        index_output_stream.close();

        SILK_TRACE << "[index] renaming " << tmp_index_path.string() << " as " << index_path_.string();
        std::filesystem::rename(tmp_index_path, index_path_);

        return false;
    }

    void reset_new_salt() {
        built_ = false;
        building_strategy_->clear();
        salt_++;
        hasher_->reset_seed(salt_);
    }

    /** Return the value associated with the given 128-bit hash.
     * Note that this method is mainly useful for benchmarking.
     * @param hash a 128-bit hash.
     * @return the associated value.
     */
    std::size_t operator()(const hash128_t& hash) const {
        ensure(built_, "RecSplit: perfect hash function not built yet");
        ensure(key_count_ > 0, "RecSplit: invalid lookup with zero keys, use empty() to guard");

        if (key_count_ == 1) {
            return 0;
        }

        const std::size_t bucket = hash128_to_bucket(hash);
        uint64_t cum_keys{0}, cum_keys_next{0}, bit_pos{0};
        double_ef_index_.get3(bucket, cum_keys, cum_keys_next, bit_pos);

        // Number of keys in this bucket
        std::size_t m = cum_keys_next - cum_keys;
        auto reader = golomb_rice_codes_.reader();
        reader.read_reset(bit_pos, skip_bits(m));
        int level = 0;

        while (m > kUpperAggregationBound) {  // fanout = 2
            const auto d = reader.read_next(golomb_param(m, memo));
            const std::size_t hmod = remap16(remix(hash.second + d + kStartSeed[level]), m);

            const std::size_t split = ((static_cast<uint16_t>((m + 1) / 2 + kUpperAggregationBound - 1) / kUpperAggregationBound)) * kUpperAggregationBound;
            if (hmod < split) {
                m = split;
            } else {
                reader.skip_subtree(skip_nodes(split), skip_bits(split));
                m -= split;
                cum_keys += split;
            }
            level++;
        }
        if (m > kLowerAggregationBound) {
            const auto d = reader.read_next(golomb_param(m, memo));
            const size_t hmod = remap16(remix(hash.second + d + kStartSeed[level]), m);

            const int part = uint16_t(hmod) / kLowerAggregationBound;
            m = min(kLowerAggregationBound, m - part * kLowerAggregationBound);
            cum_keys += kLowerAggregationBound * part;
            if (part) reader.skip_subtree(skip_nodes(kLowerAggregationBound) * part, skip_bits(kLowerAggregationBound) * part);
            level++;
        }

        if (m > LEAF_SIZE) {
            const auto d = reader.read_next(golomb_param(m, memo));
            const size_t hmod = remap16(remix(hash.second + d + kStartSeed[level]), m);

            const int part = uint16_t(hmod) / LEAF_SIZE;
            m = min(LEAF_SIZE, m - part * LEAF_SIZE);
            cum_keys += LEAF_SIZE * part;
            if (part) reader.skip_subtree(part, skip_bits(LEAF_SIZE) * part);
            level++;
        }

        const auto b = reader.read_next(golomb_param(m, memo));
        return cum_keys + remap16(remix(hash.second + b + kStartSeed[level]), m);
    }

    //! Return the value associated with the given key within the MPHF mapping
    std::size_t operator()(const std::string& key) const { return operator()(murmur_hash_3(key.c_str(), key.size())); }

    //! Return the value associated with the given key within the index
    [[nodiscard]] std::size_t lookup(ByteView key) const { return lookup(key.data(), key.size()); }

    //! Return the value associated with the given key within the index
    [[nodiscard]] std::size_t lookup(const std::string& key) const { return lookup(key.data(), key.size()); }

    //! Return the value associated with the given key within the index
    std::size_t lookup(const void* key, const size_t length) const {
        const auto record = operator()(murmur_hash_3(key, length));
        const auto position = 1 + 8 + bytes_per_record_ * (record + 1);

        const auto address = encoded_file_->address();
        ensure(position + sizeof(uint64_t) < encoded_file_->length(),
               "position: " + std::to_string(position) + " plus 8 exceeds file length");
        return endian::load_big_u64(address + position) & record_mask_;
    }

    //! Return the offset of the i-th element in the index. Perfect hash table lookup is not performed,
    //! only access to the Elias-Fano structure containing all offsets
    [[nodiscard]] std::size_t ordinal_lookup(uint64_t i) const { return ef_offsets_->get(i); }

    //! Return the number of keys used to build the RecSplit instance
    [[nodiscard]] std::size_t key_count() const { return key_count_; }

    [[nodiscard]] bool empty() const { return key_count_ == 0; }
    [[nodiscard]] uint64_t base_data_id() const { return base_data_id_; }
    [[nodiscard]] uint64_t record_mask() const { return record_mask_; }
    [[nodiscard]] uint64_t bucket_count() const { return bucket_count_; }
    [[nodiscard]] uint16_t bucket_size() const { return bucket_size_; }

    [[nodiscard]] std::size_t file_size() const { return std::filesystem::file_size(index_path_); }

    [[nodiscard]] std::filesystem::file_time_type last_write_time() const {
        return std::filesystem::last_write_time(index_path_);
    }

    [[nodiscard]] uint8_t* memory_file_address() const { return encoded_file_ ? encoded_file_->address() : nullptr; }
    [[nodiscard]] std::size_t memory_file_size() const { return encoded_file_ ? encoded_file_->length() : 0; }

  private:
    static inline std::size_t skip_bits(std::size_t m) { return memo[m] & 0xFFFF; }

    static inline std::size_t skip_nodes(std::size_t m) { return (memo[m] >> 16) & 0x7FF; }

    static inline uint64_t golomb_param(const std::size_t m,
                                        const std::array<uint32_t, kMaxBucketSize>& memo) {
        return memo[m] >> 27;
    }
    static inline uint64_t golomb_param_with_max_calculation(const std::size_t m,
                                                             const std::array<uint32_t, kMaxBucketSize>& memo,
                                                             uint16_t& golomb_param_max_index) {
        if (m > golomb_param_max_index) golomb_param_max_index = m;
        return golomb_param(m, memo);
    }

    // Generates the precomputed table of 32-bit values holding the Golomb-Rice code
    // of a splitting (upper 5 bits), the number of nodes in the associated subtree
    // (following 11 bits) and the sum of the Golomb-Rice code lengths in the same
    // subtree (lower 16 bits).
    static constexpr void precompute_golomb_rice(const int m, std::array<uint32_t, kMaxBucketSize>* memo) {
        std::array<std::size_t, kMaxFanout> k{0};

        const auto [fanout, unit] = SplitStrategy::split_params(m);

        k[fanout - 1] = m;
        for (std::size_t i{0}; i < fanout - 1; ++i) {
            k[i] = unit;
            k[fanout - 1] -= k[i];
        }

        double sqrt_prod = 1;
        for (std::size_t i{0}; i < fanout; ++i) {
            sqrt_prod *= sqrt(k[i]);
        }

        const double p = sqrt(m) / (pow(2 * std::numbers::pi, (static_cast<double>(fanout) - 1.) * 0.5) * sqrt_prod);
        auto golomb_rice_length = static_cast<uint32_t>(ceil(log2(-std::log((sqrt(5) + 1) * 0.5) / log1p(-p))));  // log2 Golomb modulus

        SILKWORM_ASSERT(golomb_rice_length <= 0x1F);  // Golomb-Rice code, stored in the 5 upper bits
        (*memo)[m] = golomb_rice_length << 27;
        for (std::size_t i{0}; i < fanout; ++i) {
            golomb_rice_length += (*memo)[k[i]] & 0xFFFF;
        }
        SILKWORM_ASSERT(golomb_rice_length <= 0xFFFF);  // Sum of Golomb-Rice code lengths in the subtree, stored in the lower 16 bits
        (*memo)[m] |= golomb_rice_length;

        uint32_t nodes = 1;
        for (std::size_t i{0}; i < fanout; ++i) {
            nodes += ((*memo)[k[i]] >> 16) & 0x7FF;
        }
        SILKWORM_ASSERT(LEAF_SIZE < 3 || nodes <= 0x7FF);  // Number of nodes in the subtree, stored in the middle 11 bits
        (*memo)[m] |= nodes << 16;
    }

    static constexpr std::array<uint32_t, kMaxBucketSize> fill_golomb_rice() {
        std::array<uint32_t, kMaxBucketSize> memo{0};
        std::size_t s{0};
        for (; s <= LEAF_SIZE; ++s) {
            memo[s] = bij_memo[s] << 27 | (s > 1) << 16 | bij_memo[s];
        }
        for (; s < kMaxBucketSize; ++s) {
            precompute_golomb_rice(static_cast<int>(s), &memo);
        }
        return memo;
    }

    //! Apply the RecSplit algorithm to the given bucket
    template <typename GRBUILDER>
    static void recsplit(std::vector<uint64_t>& keys,
                         std::vector<uint64_t>& offsets,
                         std::vector<uint64_t>& buffer_keys,     // temporary buffer for keys
                         std::vector<uint64_t>& buffer_offsets,  // temporary buffer for offsets
                         GRBUILDER& gr_builder,
                         std::ostream& index_ofs,
                         uint16_t& golomb_param_max_index,
                         uint8_t bytes_per_record) {
        recsplit(/*.level=*/0, keys, offsets, buffer_keys, buffer_offsets, /*.start=*/0, /*.end=*/keys.size(),
                 gr_builder, index_ofs, golomb_param_max_index, bytes_per_record);
    }

    template <typename GRBUILDER>
    static void recsplit(int level,  // NOLINT
                         std::vector<uint64_t>& keys,
                         std::vector<uint64_t>& offsets,         // aka values
                         std::vector<uint64_t>& buffer_keys,     // temporary buffer for keys
                         std::vector<uint64_t>& buffer_offsets,  // temporary buffer for offsets
                         std::size_t start,
                         std::size_t end,
                         GRBUILDER& gr_builder,
                         std::ostream& index_ofs,
                         uint16_t& golomb_param_max_index,
                         uint8_t bytes_per_record) {
        uint64_t salt = kStartSeed[level];
        const std::size_t m = end - start;
        SILKWORM_ASSERT(m > 1);
        if (m <= LEAF_SIZE) {
            // No need to build aggregation levels - just find bijection
            SILK_TRACE << "[index] recsplit level " << level << ", m=" << m << " < leaf size, just find bijection";
            if (level == 7) {
                SILK_TRACE << "[index] recsplit m: " << m << " salt: " << salt << " start: " << start << " bucket[start]=" << keys[start];
                for (std::size_t j = 0; j < m; j++) {
                    SILK_TRACE << "[index] buffer m: " << m << " start: " << start << " j: " << j << " bucket[start + j]=" << keys[start + j];
                }
            }
            while (true) {
                uint32_t mask{0};
                bool fail{false};
                for (uint16_t i{0}; !fail && i < m; i++) {
                    uint32_t bit = uint32_t(1) << remap16(remix(keys[start + i] + salt), m);
                    if ((mask & bit) != 0) {
                        fail = true;
                    } else {
                        mask |= bit;
                    }
                }
                if (!fail) break;
                salt++;
            }
            for (std::size_t i{0}; i < m; i++) {
                std::size_t j = remap16(remix(keys[start + i] + salt), m);
                buffer_offsets[j] = offsets[start + i];
            }
            Bytes uint64_buffer(8, '\0');
            for (std::size_t i{0}; i < m; i++) {
                endian::store_big_u64(uint64_buffer.data(), buffer_offsets[i]);
                index_ofs.write(reinterpret_cast<const char*>(uint64_buffer.data() + (8 - bytes_per_record)), bytes_per_record);
                if (level == 0) {
                    SILK_TRACE << "[index] written offset: " << buffer_offsets[i];
                }
            }
            salt -= kStartSeed[level];
            const auto log2golomb = golomb_param_with_max_calculation(m, memo, golomb_param_max_index);
            gr_builder.append_fixed(salt, log2golomb);
            gr_builder.append_unary(static_cast<uint32_t>(salt >> log2golomb));
        } else {
            const auto [fanout, unit] = SplitStrategy::split_params(m);

            SILK_TRACE << "[index] recsplit level " << level << ", m=" << m << " > leaf size, fanout=" << fanout << " unit=" << unit;
            SILKWORM_ASSERT(fanout <= kLowerAggregationBound);

            std::vector<std::size_t> count(fanout, 0);  // temporary counters of key remapped occurrences
            while (true) {
                std::fill(count.begin(), count.end(), 0);
                for (std::size_t i{0}; i < m; i++) {
                    count[uint16_t(remap16(remix(keys[start + i] + salt), m)) / unit]++;
                }
                bool broken{false};
                for (std::size_t i = 0; i < fanout - 1; i++) {
                    broken = broken || (count[i] != unit);
                }
                if (!broken) break;
                salt++;
            }
            for (std::size_t i{0}, c{0}; i < fanout; i++, c += unit) {
                count[i] = c;
            }
            for (std::size_t i{0}; i < m; i++) {
                auto j = uint16_t(remap16(remix(keys[start + i] + salt), m)) / unit;
                buffer_keys[count[j]] = keys[start + i];
                buffer_offsets[count[j]] = offsets[start + i];
                count[j]++;
            }
            std::copy(buffer_keys.data(), buffer_keys.data() + m, keys.data() + start);
            std::copy(buffer_offsets.data(), buffer_offsets.data() + m, offsets.data() + start);

            salt -= kStartSeed[level];
            const auto log2golomb = golomb_param_with_max_calculation(m, memo, golomb_param_max_index);
            gr_builder.append_fixed(salt, log2golomb);
            gr_builder.append_unary(static_cast<uint32_t>(salt >> log2golomb));

            std::size_t i{0};
            for (; i < m - unit; i += unit) {
                recsplit(level + 1, keys, offsets, buffer_keys, buffer_offsets, start + i, start + i + unit, gr_builder, index_ofs, golomb_param_max_index, bytes_per_record);
            }
            if (m - i > 1) {
                recsplit(level + 1, keys, offsets, buffer_keys, buffer_offsets, start + i, end, gr_builder, index_ofs, golomb_param_max_index, bytes_per_record);
            } else if (m - i == 1) {
                Bytes uint64_buffer(8, '\0');
                endian::store_big_u64(uint64_buffer.data(), offsets[start + i]);
                index_ofs.write(reinterpret_cast<const char*>(uint64_buffer.data() + (8 - bytes_per_record)), bytes_per_record);
                if (level == 0) {
                    SILK_TRACE << "[index] written offset: " << offsets[start + i];
                }
            }
        }
    }

    hash128_t inline murmur_hash_3(const void* data, const size_t length) const {
        hash128_t h{};
        hasher_->hash_x64_128(data, length, &h);
        return h;
    }

    // Maps a 128-bit to a bucket using the first 64-bit half.
    [[nodiscard]] inline uint64_t hash128_to_bucket(const hash128_t& hash) const { return remap128(hash.first, bucket_count_); }

    void check_minimum_length(std::size_t minimum_length) {
        if (encoded_file_ && encoded_file_->length() < minimum_length) {
            throw std::runtime_error("RecSplit encoded file is too short: " + std::to_string(encoded_file_->length()));
        }
    }

    friend std::ostream& operator<<(std::ostream& os, const RecSplit<LEAF_SIZE>& rs) {
        size_t leaf_size = LEAF_SIZE;
        os.write(reinterpret_cast<char*>(&leaf_size), sizeof(leaf_size));
        os.write(reinterpret_cast<char*>(&rs.bucket_size_), sizeof(rs.bucket_size_));
        os.write(reinterpret_cast<char*>(&rs.key_count_), sizeof(rs.key_count_));
        os << rs.golomb_rice_codes_;
        os << rs.double_ef_index_;
        return os;
    }

    friend std::istream& operator>>(std::istream& is, RecSplit<LEAF_SIZE>& rs) {
        size_t leaf_size{0};
        is.read(reinterpret_cast<char*>(&leaf_size), sizeof(leaf_size));
        if (leaf_size != LEAF_SIZE) {
            fprintf(stderr, "Serialized leaf size %d, code leaf size %d\n", int(leaf_size), int(LEAF_SIZE));
            abort();
        }
        is.read(reinterpret_cast<char*>(&rs.bucket_size_), sizeof(rs.bucket_size_));
        is.read(reinterpret_cast<char*>(&rs.key_count_), sizeof(rs.key_count_));
        rs.bucket_count_ = max(1, (rs.key_count_ + rs.bucket_size_ - 1) / rs.bucket_size_);

        is >> rs.golomb_rice_codes_;
        is >> rs.double_ef_index_;
        return is;
    }

    static const std::size_t kLowerAggregationBound;

    static const std::size_t kUpperAggregationBound;

    //! The max index used in Golomb parameter array
    uint16_t golomb_param_max_index_{0};

    //! For each bucket size, the Golomb-Rice parameter (upper 8 bits) and the number of bits to
    //! skip in the fixed part of the tree (lower 24 bits).
    static const std::array<uint32_t, kMaxBucketSize> memo;

    //! The size in bytes of each Recsplit bucket (possibly except the last one)
    uint16_t bucket_size_;

    //! The number of keys for this Recsplit algorithm instance
    std::size_t key_count_;

    //! The number of buckets for this Recsplit algorithm instance
    std::size_t bucket_count_;

    //! The Golomb-Rice (GR) codes of splitting and bijection indices
    GolombRiceVector golomb_rice_codes_;

    //! Double Elias-Fano (EF) index for bucket cumulative keys and bit positions
    DoubleEliasFano double_ef_index_;

    //! Helper to encode the sequences of key offsets in the single EF code
    std::unique_ptr<EliasFano> ef_offsets_;

    //! Minimal app-specific ID of entries of this index - helps app understand what data stored in given shard - persistent field
    uint64_t base_data_id_;

    //! The path of the index file generated
    std::filesystem::path index_path_;

    //! Number of bytes used per index record
    uint8_t bytes_per_record_{0};

    //! The bitmask to be used to interpret record data
    uint64_t record_mask_{0};

    //! Flag indicating if two-level index "recsplit -> enum" + "enum -> offset" is required
    bool double_enum_index_{true};

    //! Flag indicating that the MPHF has been built and no more keys can be added
    bool built_{false};

    //! The offset collector for Elias-Fano encoding of "enum -> offset" index
    std::vector<uint64_t> offsets_;

    //! Seed for Murmur3 hash used for converting keys to 64-bit values and assigning to buckets
    uint32_t salt_{0};

    //! Murmur3 hash factory
    std::unique_ptr<Murmur3> hasher_;

    //! The memory-mapped RecSplit-encoded file when opening existing index for read
    std::optional<MemoryMappedFile> encoded_file_;

    std::unique_ptr<BuildingStrategy> building_strategy_;
};

//! The sequential building strategy
template <std::size_t LEAF_SIZE>
struct RecSplit<LEAF_SIZE>::SequentialBuildingStrategy : public BuildingStrategy {
    explicit SequentialBuildingStrategy(std::size_t etl_optimal_size) : etl_optimal_size_{etl_optimal_size} {}

  protected:
    void init(std::size_t bucket_size, std::size_t bucket_count, std::size_t, bool double_enum_index) override {
        offset_collector_ = std::make_unique<etl::Collector>(etl_optimal_size_);
        bucket_collector_ = std::make_unique<etl::Collector>(etl_optimal_size_);

        bucket_size_accumulator_.reserve(bucket_count + 1);
        bucket_position_accumulator_.reserve(bucket_count + 1);
        bucket_size_accumulator_.resize(1);      // Start with 0 as bucket accumulated size
        bucket_position_accumulator_.resize(1);  // Start with 0 as bucket accumulated position
        current_bucket_.reserve(bucket_size);
        current_bucket_offsets_.reserve(bucket_size);
        double_enum_index_ = double_enum_index;
    }

    void add_key(uint64_t bucket_id, uint64_t bucket_key, uint64_t offset) override {
        if (keys_added_ % 100'000 == 0) {
            SILK_DEBUG << "[index] add key hash: bucket_id=" << bucket_id << " bucket_key=" << bucket_key << " offset=" << offset;
        }

        if (offset > max_offset_) {
            max_offset_ = offset;
        }

        // if (keys_added_ > 0) {  // unused
        //     const auto delta = offset - previous_offset_;
        //     if (keys_added_ == 1 || delta < min_delta_) {
        //         min_delta_ = delta;
        //     }
        // }

        Bytes collector_key(16, '\0');
        endian::store_big_u64(collector_key.data(), bucket_id);
        endian::store_big_u64(collector_key.data() + sizeof(uint64_t), bucket_key);
        Bytes offset_key(8, '\0');
        endian::store_big_u64(offset_key.data(), offset);

        if (this->double_enum_index_) {
            offset_collector_->collect(offset_key, {});

            Bytes current_key_count(8, '\0');
            endian::store_big_u64(current_key_count.data(), keys_added_);
            bucket_collector_->collect(collector_key, current_key_count);
        } else {
            bucket_collector_->collect(collector_key, offset_key);
        }

        keys_added_++;
        // previous_offset_ = offset;
    }

    bool build_mph_index(std::ofstream& index_output_stream, GolombRiceVector& golomb_rice_codes, uint16_t& golomb_param_max_index,
                         DoubleEliasFano& double_ef_index, uint8_t bytes_per_record) override {
        current_bucket_id_ = std::numeric_limits<uint64_t>::max();  // To make sure 0 bucket is detected

        [[maybe_unused]] auto _ = gsl::finally([&]() { bucket_collector_->clear(); });

        // We use an exception for collision error condition because ETL currently does not support loading errors
        // TODO(canepat) refactor ETL to support errors in LoadFunc and propagate them to caller to get rid of CollisionError
        struct CollisionError : public std::runtime_error {
            explicit CollisionError(uint64_t _bucket_id) : runtime_error("collision"), bucket_id(_bucket_id) {}
            uint64_t bucket_id;
        };
        try {
            // Passing a void cursor is valid case for ETL when DB modification is not expected
            db::PooledCursor empty_cursor{};
            bucket_collector_->load(empty_cursor, [&](const etl::Entry& entry, auto&, MDBX_put_flags_t) {
                // k is the big-endian encoding of the bucket number and the v is the key that is assigned into that bucket
                const uint64_t bucket_id = endian::load_big_u64(entry.key.data());
                SILK_TRACE << "[index] processing bucket_id=" << bucket_id;
                if (current_bucket_id_ != bucket_id) {
                    if (current_bucket_id_ != std::numeric_limits<uint64_t>::max()) {
                        bool collision = recsplit_current_bucket(index_output_stream, golomb_param_max_index, bytes_per_record);
                        if (collision) throw CollisionError{bucket_id};
                    }
                    current_bucket_id_ = bucket_id;
                }
                current_bucket_.emplace_back(endian::load_big_u64(entry.key.data() + sizeof(uint64_t)));
                current_bucket_offsets_.emplace_back(endian::load_big_u64(entry.value.data()));
            });
        } catch (const CollisionError& error) {
            SILK_WARN << "[index] collision detected for bucket=" << error.bucket_id;
            return true;
        }
        if (!current_bucket_.empty()) {
            bool collision_detected = recsplit_current_bucket(index_output_stream, golomb_param_max_index, bytes_per_record);
            if (collision_detected) return true;
        }

        gr_builder_.append_fixed(1, 1);  // Sentinel (avoids checking for parts of size 1)

        // Concatenate the representation of each bucket
        golomb_rice_codes = gr_builder_.build();

        // Construct double Elias-Fano index for bucket cumulative keys and bit positions
        std::vector<uint64_t> cumulative_keys{bucket_size_accumulator_.begin(), bucket_size_accumulator_.end()};
        std::vector<uint64_t> positions(bucket_position_accumulator_.begin(), bucket_position_accumulator_.end());
        double_ef_index.build(cumulative_keys, positions);

        return false;  // no collision
    }

    void build_enum_index(std::unique_ptr<EliasFano>& ef_offsets) override {
        // Build Elias-Fano index for offsets (if any)
        ef_offsets = std::make_unique<EliasFano>(keys_added_, max_offset_);
        db::PooledCursor empty_cursor{};
        offset_collector_->load(empty_cursor, [&](const etl::Entry& entry, auto&, MDBX_put_flags_t) {
            const uint64_t offset = endian::load_big_u64(entry.key.data());
            ef_offsets->add_offset(offset);
        });
        ef_offsets->build();
    }

    //! Compute and store the splittings and bijections of the current bucket
    bool recsplit_current_bucket(std::ofstream& index_output_stream, uint16_t& golomb_param_max_index, uint8_t bytes_per_record) {
        // Extend bucket size accumulator to accommodate current bucket index + 1
        while (bucket_size_accumulator_.size() <= (current_bucket_id_ + 1)) {
            bucket_size_accumulator_.push_back(bucket_size_accumulator_.back());
        }
        bucket_size_accumulator_.back() += current_bucket_.size();
        SILKWORM_ASSERT(bucket_size_accumulator_.back() >= bucket_size_accumulator_[current_bucket_id_]);

        // Sets of size 0 and 1 are not further processed, just write them to index
        if (current_bucket_.size() > 1) {
            for (std::size_t i{1}; i < current_bucket_.size(); ++i) {
                if (current_bucket_[i] == current_bucket_[i - 1]) {
                    SILK_TRACE << "collision detected key=" << current_bucket_[i - 1];
                    return true;
                }
            }
            buffer_bucket_.reserve(current_bucket_.size());
            buffer_offsets_.reserve(current_bucket_offsets_.size());
            buffer_bucket_.resize(current_bucket_.size());
            buffer_offsets_.resize(current_bucket_.size());

            RecSplit<LEAF_SIZE>::recsplit(
                current_bucket_, current_bucket_offsets_, buffer_bucket_, buffer_offsets_, gr_builder_,
                index_output_stream, golomb_param_max_index, bytes_per_record);
            gr_builder_.append_collected_unaries();
        } else {
            for (const auto offset : current_bucket_offsets_) {
                Bytes uint64_buffer(8, '\0');
                endian::store_big_u64(uint64_buffer.data(), offset);
                index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), 8);
                SILK_TRACE << "[index] written offset: " << offset;
            }
        }
        // Extend bucket position accumulator to accommodate current bucket index + 1
        while (bucket_position_accumulator_.size() <= current_bucket_id_ + 1) {
            bucket_position_accumulator_.push_back(bucket_position_accumulator_.back());
        }
        bucket_position_accumulator_.back() = gr_builder_.get_bits();
        SILKWORM_ASSERT(bucket_position_accumulator_.back() >= bucket_position_accumulator_[current_bucket_id_]);

        // Clear for the next bucket
        current_bucket_.clear();
        current_bucket_offsets_.clear();
        buffer_bucket_.clear();
        buffer_offsets_.clear();
        return false;
    }

    void clear() override {
        bucket_collector_->clear();
        offset_collector_->clear();
        current_bucket_.clear();
        current_bucket_offsets_.clear();
        bucket_size_accumulator_.resize(1);
        bucket_position_accumulator_.resize(1);
        keys_added_ = 0;
        max_offset_ = 0;
    }

    uint64_t keys_added() override {
        return keys_added_;
    }

    uint64_t max_offset() override {
        return max_offset_;
    }

  private:
    // Optimal size for offset and bucket ETL collectors
    std::size_t etl_optimal_size_{etl::kOptimalBufferSize};

    //! Flag indicating if two-level index "recsplit -> enum" + "enum -> offset" is required
    bool double_enum_index_{false};

    //! Maximum value of offset used to decide how many bytes to use for Elias-Fano encoding
    uint64_t max_offset_{0};

    //! The number of keys currently added
    uint64_t keys_added_{0};

    //! Identifier of the current bucket being accumulated
    uint64_t current_bucket_id_{0};

    //! 64-bit fingerprints of keys in the current bucket accumulated before the recsplit is performed for that bucket
    std::vector<uint64_t> current_bucket_;

    //! Index offsets for the current bucket
    std::vector<uint64_t> current_bucket_offsets_;

    //! The ETL collector sorting keys by offset
    std::unique_ptr<etl::Collector> offset_collector_{};

    //! The ETL collector sorting keys by bucket
    std::unique_ptr<etl::Collector> bucket_collector_{};

    //! Accumulator for size of every bucket
    std::vector<int64_t> bucket_size_accumulator_;

    //! Accumulator for position of every bucket in the encoding of the hash function
    std::vector<int64_t> bucket_position_accumulator_;

    //! Temporary buffer for current bucket
    std::vector<uint64_t> buffer_bucket_;

    //! Temporary buffer for current offsets
    std::vector<uint64_t> buffer_offsets_;

    //! Helper to build GR codes of splitting and bijection indices
    GolombRiceBuilder gr_builder_;

    //! Minimum delta for Elias-Fano encoding of "enum -> offset" index
    // uint64_t min_delta_{0};  // unused

    //! Last previously added offset (for calculating minimum delta for Elias-Fano encoding of "enum -> offset" index)
    // uint64_t previous_offset_{0};  // unused
};

constexpr std::size_t kLeafSize{8};

using RecSplit8 = RecSplit<kLeafSize>;

template <>
const std::array<uint32_t, kMaxBucketSize> RecSplit8::memo;

using RecSplitIndex = RecSplit8;

inline auto seq_build_strategy() { return std::make_unique<RecSplit8::SequentialBuildingStrategy>(etl::kOptimalBufferSize); }

/* Example usage:
    RecSplit8 recsplit{RecSplitSettings{}, std::make_unique<RecSplit8::SequentialBuildingStrategy>(etl::kOptimalBufferSize)};
    auto collision = recsplit.build();
 */

}  // namespace silkworm::succinct

#pragma GCC diagnostic pop
