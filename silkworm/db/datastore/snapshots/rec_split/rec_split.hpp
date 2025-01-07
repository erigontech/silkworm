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

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cmath>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <numbers>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <absl/functional/function_ref.h>
#include <gsl/narrow>
#include <gsl/util>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/math.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/memory_mapped_file.hpp>

#include "../common/util/bitmask_operators.hpp"
#include "../elias_fano/elias_fano.hpp"
#include "golomb_rice.hpp"
#include "murmur_hash3.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"

namespace silkworm::snapshots::rec_split {

using namespace std::chrono;
using encoding::remap16, encoding::remap128;

//! Assumed *maximum* size of a bucket. Works with high probability up to average bucket size ~2000
inline constexpr int kMaxBucketSize = 3000;

//! Assumed *maximum* size of splitting tree leaves
inline constexpr int kMaxLeafSize = 24;

//! Assumed *maximum* size of splitting tree fanout
inline constexpr int kMaxFanout = 32;

//! Starting seed at given distance from the root (extracted at random)
inline constexpr std::array<uint64_t, 20> kStartSeed = {
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
struct Hash128 {
    uint64_t first;   // The high 64-bit hash half
    uint64_t second;  // The low 64-bit hash half

    bool operator<(const Hash128& o) const { return first < o.first || second < o.second; }
};

// Optimal Golomb-Rice parameters for leaves
inline constexpr uint8_t kBijMemo[] = {0, 0, 0, 1, 3, 4, 5, 7, 8, 10, 11, 12, 14, 15, 16, 18, 19, 21, 22, 23, 25, 26, 28, 29, 30};

//! The splitting strategy of Recsplit algorithm is embedded into the generation code, which uses only the public fields
template <size_t LEAF_SIZE>
class SplittingStrategy {
    static_assert(1 <= LEAF_SIZE && LEAF_SIZE <= kMaxLeafSize);

  public:
    //! The lower bound for primary (lower) key aggregation
    static constexpr size_t kLowerAggregationBound = LEAF_SIZE * std::max(size_t{2},
                                                                          math::int_ceil<size_t>(0.35 * LEAF_SIZE + 0.5));

    //! The lower bound for secondary (upper) key aggregation
    static constexpr size_t kUpperAggregationBound = kLowerAggregationBound * (LEAF_SIZE < 7 ? size_t{2}
                                                                                             : math::int_ceil<size_t>(0.21 * LEAF_SIZE + 0.9));

    static std::pair<size_t, size_t> split_params(const size_t m) {
        size_t fanout{0}, unit{0};
        if (m > kUpperAggregationBound) {  // High-level aggregation (fanout 2)
            unit = kUpperAggregationBound * (static_cast<uint16_t>((m + 1) / 2 + kUpperAggregationBound - 1) / kUpperAggregationBound);
            fanout = 2;
        } else if (m > kLowerAggregationBound) {  // Second-level aggregation
            unit = kLowerAggregationBound;
            fanout = static_cast<uint16_t>(m + kLowerAggregationBound - 1) / kLowerAggregationBound;
        } else {  // First-level aggregation
            unit = LEAF_SIZE;
            fanout = static_cast<uint16_t>(m + LEAF_SIZE - 1) / LEAF_SIZE;
        }
        return {fanout, unit};
    }
};

//! Size in bytes of 1st fixed metadata header fields in RecSplit-encoded file
inline constexpr size_t kBaseDataIdLength = sizeof(uint64_t);
inline constexpr size_t kKeyCountLength = sizeof(uint64_t);
inline constexpr size_t kBytesPerRecordLength = sizeof(uint8_t);

//! Size in bytes of 1st fixed metadata header in RecSplit-encoded file
inline constexpr size_t kFirstMetadataHeaderLength =
    kBaseDataIdLength + kKeyCountLength + kBytesPerRecordLength;

//! Size in bytes of 2nd fixed metadata header fields in RecSplit-encoded file
inline constexpr size_t kBucketCountLength = sizeof(uint64_t);
inline constexpr size_t kBucketSizeLength = sizeof(uint16_t);
inline constexpr size_t kLeafSizeLength = sizeof(uint16_t);
inline constexpr size_t kSaltSizeLength = sizeof(uint32_t);
inline constexpr size_t kStartSeedSizeLength = sizeof(uint8_t);

inline constexpr size_t kFeaturesFlagLength = sizeof(uint8_t);
inline constexpr size_t kGolombParamSizeLength = sizeof(uint32_t);  // Erigon writes 4-instead-of-2 bytes
inline constexpr size_t kEliasFano32CountLength = sizeof(uint64_t);
inline constexpr size_t kEliasFano32ULength = sizeof(uint64_t);
inline constexpr size_t kExistenceFilterSizeLength = sizeof(uint64_t);

//! Size in bytes of 2nd fixed metadata header in RecSplit-encoded file
inline constexpr size_t kSecondMetadataHeaderLength =
    kBucketCountLength + kBucketSizeLength + kLeafSizeLength + kSaltSizeLength + kStartSeedSizeLength;

//! Parameters for modified Recursive splitting (RecSplit) algorithm.
struct RecSplitSettings {
    size_t keys_count;                 // The total number of keys in the RecSplit
    uint16_t bucket_size;              // The number of keys in each bucket (except probably last one)
    std::filesystem::path index_path;  // The path of the generated RecSplit index file
    uint64_t base_data_id;             // Application-specific base data ID written in index header
    bool double_enum_index{true};      // Flag indicating if 2-layer index is required
    bool less_false_positives{false};  // Flag indicating if existence filter to reduce false-positives is required
};

enum class RecSplitFeatures : uint8_t {
    kNone = 0b0,                 // no specific feature
    kEnums = 0b1,                // 2-layer index with PHT pointing to enumeration and enumeration pointing to offsets
    kLessFalsePositives = 0b10,  // reduce false-positives to 1/256=0.4% at the cost of 1byte per key
};
consteval void enable_bitmask_operator_and(RecSplitFeatures);
consteval void enable_bitmask_operator_or(RecSplitFeatures);
consteval void enable_bitmask_operator_not(RecSplitFeatures);

inline constexpr std::array kSupportedFeatures{RecSplitFeatures::kEnums, RecSplitFeatures::kLessFalsePositives};

//! Recursive splitting (RecSplit) is an efficient algorithm to identify minimal perfect hash functions.
//! The template parameter LEAF_SIZE decides how large a leaf will be. Larger leaves imply slower construction, but less
//! space and faster evaluation
//! @tparam LEAF_SIZE the size of a leaf, typical value range from 6 to 8 for fast small maps or up to 16 for very compact functions
template <size_t LEAF_SIZE>
class RecSplit {
  public:
    using SplitStrategy = SplittingStrategy<LEAF_SIZE>;
    using GolombRiceBuilder = GolombRiceVector::Builder;
    using EliasFano = elias_fano::EliasFanoList32;
    using DoubleEliasFano = elias_fano::DoubleEliasFanoList16;

    //! The base class for RecSplit building strategies
    struct BuildingStrategy {
        virtual ~BuildingStrategy() = default;

        virtual void setup(const RecSplitSettings& settings, size_t bucket_count) = 0;

        virtual void add_key(uint64_t bucket_id, uint64_t bucket_key, uint64_t offset) = 0;
        virtual bool build_mph_index(
            std::ofstream& index_output_stream,
            GolombRiceVector& golomb_rice_codes,
            uint16_t& golomb_param_max_index,
            DoubleEliasFano& double_ef_index,
            uint8_t bytes_per_record) = 0;
        virtual void build_enum_index(std::unique_ptr<EliasFano>& ef_offsets) = 0;
        virtual void clear() = 0;

        virtual uint64_t keys_added() = 0;
        virtual uint64_t max_offset() = 0;

        void add_to_existence_filter(uint8_t key_fingerprint) {
            existence_filter_stream_ << key_fingerprint;
        }

        void flush_existence_filter(Bytes& uint64_buffer, std::ofstream& index_output_stream) {
            existence_filter_stream_.flush();
            existence_filter_stream_.seekg(0, std::ios::beg);
            endian::store_big_u64(uint64_buffer.data(), keys_added());
            index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
            index_output_stream << existence_filter_stream_.rdbuf();
        }

      protected:
        BuildingStrategy()
            : existence_filter_stream_{TemporaryDirectory::get_unique_temporary_path(),
                                       std::ios::binary | std::ios::out | std::ios::in | std::ios::app} {}

      private:
        //! Serialization for the existence filter (1-byte per key positional presence hint)
        std::fstream existence_filter_stream_;
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
          less_false_positives_(settings.less_false_positives),
          building_strategy_(std::move(bs)) {
        building_strategy_->setup(settings, bucket_count_);

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

        const auto address = encoded_file_->region().data();

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
        for (size_t i{0}; i < start_seed_length; ++i) {
            start_seed[i] = endian::load_big_u64(address + offset);
            offset += sizeof(uint64_t);
        }
        SILKWORM_ASSERT(start_seed == kStartSeed);

        // Read features flag (see RecSplitFeatures)
        check_minimum_length(offset + kFeaturesFlagLength);
        const RecSplitFeatures features{(address + offset)[0]};
        check_supported_features(features);
        double_enum_index_ = (features & RecSplitFeatures::kEnums) != RecSplitFeatures::kNone;
        less_false_positives_ = (features & RecSplitFeatures::kLessFalsePositives) != RecSplitFeatures::kNone;
        offset += kFeaturesFlagLength;

        if (double_enum_index_ && key_count_ > 0) {
            check_minimum_length(offset + kEliasFano32CountLength + kEliasFano32ULength);

            // Read Elias-Fano index for offsets
            const uint64_t count = endian::load_big_u64(address + offset);
            offset += kEliasFano32CountLength;
            const uint64_t u = endian::load_big_u64(address + offset);
            offset += kEliasFano32ULength;
            auto remaining_data = encoded_file_->region().subspan(offset);
            ef_offsets_ = std::make_unique<EliasFano>(count, u, remaining_data);
            offset += ef_offsets_->data().size() * sizeof(uint64_t);

            if (less_false_positives_) {
                // Read 1-byte-per-key existence filter used to reduce false positives
                const uint64_t filter_size = endian::load_big_u64(address + offset);
                offset += kExistenceFilterSizeLength;
                if (filter_size != key_count_) {
                    throw std::runtime_error{
                        "Incompatible index format: existence filter length " + std::to_string(filter_size) +
                        " != key count " + std::to_string(key_count_)};
                }
                std::span<uint8_t> filter_data{address + offset, filter_size};
                existence_filter_.resize(filter_size);
                std::copy(filter_data.begin(), filter_data.end(), existence_filter_.data());
                offset += filter_size;
            }
        }

        // Read the number of Golomb-Rice code params
        check_minimum_length(offset + kGolombParamSizeLength);
        const uint16_t golomb_param_size = endian::load_big_u16(address + offset);
        golomb_param_max_index_ = golomb_param_size - 1;
        offset += kGolombParamSizeLength;

        MemoryMappedInputStream mmis{encoded_file_->region().subspan(offset)};

        // Read Golomb-Rice codes
        mmis >> golomb_rice_codes_;
        offset += sizeof(uint64_t) + golomb_rice_codes_.size() * sizeof(uint64_t);

        // Read double Elias-Fano code for bucket cumulative keys and bit positions
        mmis >> double_ef_index_;
        offset += 5 * sizeof(uint64_t) + double_ef_index_.data().size() * sizeof(uint64_t);

        SILKWORM_ASSERT(offset == encoded_file_->size());

        encoded_file_->advise_random();

        // Prevent any new key addition
        built_ = true;
    }

    RecSplit(RecSplit&&) = default;
    RecSplit& operator=(RecSplit&&) noexcept = default;

    void add_key(const Hash128& key_hash, uint64_t offset) {
        if (built_) {
            throw std::logic_error{"cannot add key after perfect hash function has been built"};
        }

        uint64_t bucket_id = hash128_to_bucket(key_hash);
        auto bucket_key = key_hash.second;

        building_strategy_->add_key(bucket_id, bucket_key, offset);

        // Write first byte for each hashed key into the existence filter (if any)
        if (less_false_positives_) {
            building_strategy_->add_to_existence_filter(static_cast<uint8_t>(key_hash.first));
        }
    }

    void add_key(ByteView key, uint64_t offset) {
        if (built_) {
            throw std::logic_error{"cannot add key after perfect hash function has been built"};
        }

        const auto key_hash = murmur_hash_3(key);
        add_key(key_hash, offset);
    }

    void add_key(const std::string& key, uint64_t offset) {
        add_key(string_view_to_byte_view(key), offset);
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
        bytes_per_record_ = gsl::narrow<uint8_t>((std::bit_width(building_strategy_->max_offset()) + 7) / 8);
        index_output_stream.write(reinterpret_cast<const char*>(&bytes_per_record_), sizeof(uint8_t));
        SILK_TRACE << "[index] written bytes per record: " << int{bytes_per_record_};

        SILK_TRACE << "[index] calculating file=" << index_path_.string();

        // Compute Minimal Perfect Hash Function using RecSplit algorithm and write table: mph-output -> ordinal
        const bool collision = building_strategy_->build_mph_index(index_output_stream,
                                                                   golomb_rice_codes_,
                                                                   golomb_param_max_index_,
                                                                   double_ef_index_,
                                                                   bytes_per_record_);
        if (collision) return true;

        // Compute optional additional table: ordinal -> offset
        if (double_enum_index_) {
            building_strategy_->build_enum_index(ef_offsets_);
        }

        built_ = true;

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
        constexpr uint8_t kStartSeedLength = kStartSeed.size();
        index_output_stream.write(reinterpret_cast<const char*>(&kStartSeedLength), sizeof(uint8_t));
        SILK_TRACE << "[index] written start seed length: " << int{kStartSeedLength};

        for (const uint64_t s : kStartSeed) {
            endian::store_big_u64(uint64_buffer.data(), s);
            index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
        }
        SILK_TRACE << "[index] written start seed: first=" << kStartSeed[0] << " last=" << kStartSeed[kStartSeed.size() - 1];

        // Write out the features flag
        RecSplitFeatures features{RecSplitFeatures::kNone};
        if (double_enum_index_) {
            features = features | RecSplitFeatures::kEnums;
            if (less_false_positives_) {
                features = features | RecSplitFeatures::kLessFalsePositives;
            }
        }
        const auto features_flag = static_cast<uint8_t>(features);
        index_output_stream.write(reinterpret_cast<const char*>(&features_flag), sizeof(uint8_t));

        // Write out Elias-Fano code for offsets (if any)
        if (double_enum_index_) {
            index_output_stream << *ef_offsets_;
            SILK_TRACE << "[index] written EF code for offsets [size: " << ef_offsets_->count() - 1 << "]";

            // Write out existence filter (if any)
            if (less_false_positives_) {
                building_strategy_->flush_existence_filter(uint64_buffer, index_output_stream);
            }
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

    void build_without_collisions(absl::FunctionRef<void(RecSplit<LEAF_SIZE>&)> populate) {
        for (uint64_t iteration = 0; iteration < 10; ++iteration) {
            populate(*this);

            SILK_TRACE << "RecSplit::build..."
                       << " iteration=" << iteration;
            bool collision_detected = build();
            SILK_TRACE << "RecSplit::build done"
                       << " iteration=" << iteration;

            if (collision_detected) {
                SILK_DEBUG << "RecSplit::build collision";
                reset_new_salt();
            } else {
                return;
            }
        }
        throw std::runtime_error{"RecSplit::build_without_collisions: abort after max iterations"};
    }

    void reset_new_salt() {
        built_ = false;
        building_strategy_->clear();
        ++salt_;
        hasher_->reset_seed(salt_);
    }

    //! Check if the given bucket hash is present as i-th element in the index
    //! \return true if hash is present as i-th element, false otherwise
    bool has(const Hash128& hash, size_t i) const {
        if (less_false_positives_ && i < existence_filter_.size()) {
            return existence_filter_.at(i) == static_cast<uint8_t>(hash.first);
        }
        // If existence filter not applicable, default is true: MPHF has no presence indicator
        return true;
    }

    //! Return the value associated with the given 128-bit bucket hash
    //! \param hash a 128-bit bucket hash
    //! \return the associated value
    size_t operator()(const Hash128& hash) const {
        ensure(built_, "RecSplit: perfect hash function not built yet");
        ensure(key_count_ > 0, "RecSplit: invalid lookup with zero keys, use empty() to guard");

        if (key_count_ == 1) {
            return 0;
        }

        const size_t bucket = hash128_to_bucket(hash);
        uint64_t cum_keys{0}, cum_keys_next{0}, bit_pos{0};
        double_ef_index_.get3(bucket, cum_keys, cum_keys_next, bit_pos);

        // Number of keys in this bucket
        size_t m = cum_keys_next - cum_keys;
        auto reader = golomb_rice_codes_.reader();
        reader.read_reset(bit_pos, skip_bits(m));
        int level = 0;

        while (m > kUpperAggregationBound) {  // fanout = 2
            const auto d = reader.read_next(golomb_param(m, kMemo));
            const size_t hmod = remap16(remix(hash.second + d + kStartSeed[level]), m);

            const size_t split = ((static_cast<uint16_t>((m + 1) / 2 + kUpperAggregationBound - 1) / kUpperAggregationBound)) * kUpperAggregationBound;
            if (hmod < split) {
                m = split;
            } else {
                reader.skip_subtree(skip_nodes(split), skip_bits(split));
                m -= split;
                cum_keys += split;
            }
            ++level;
        }
        if (m > kLowerAggregationBound) {
            const auto d = reader.read_next(golomb_param(m, kMemo));
            const size_t hmod = remap16(remix(hash.second + d + kStartSeed[level]), m);

            const int part = static_cast<uint16_t>(hmod) / kLowerAggregationBound;
            m = std::min(kLowerAggregationBound, m - part * kLowerAggregationBound);
            cum_keys += kLowerAggregationBound * part;
            if (part) reader.skip_subtree(skip_nodes(kLowerAggregationBound) * part, skip_bits(kLowerAggregationBound) * part);
            ++level;
        }

        if (m > LEAF_SIZE) {
            const auto d = reader.read_next(golomb_param(m, kMemo));
            const size_t hmod = remap16(remix(hash.second + d + kStartSeed[level]), m);

            const int part = static_cast<uint16_t>(hmod) / LEAF_SIZE;
            m = std::min(LEAF_SIZE, m - part * LEAF_SIZE);
            cum_keys += LEAF_SIZE * part;
            if (part) reader.skip_subtree(part, skip_bits(LEAF_SIZE) * part);
            ++level;
        }

        const auto b = reader.read_next(golomb_param(m, kMemo));
        return cum_keys + remap16(remix(hash.second + b + kStartSeed[level]), m);
    }

    //! Return the value associated with the given key within the MPHF mapping
    size_t operator()(ByteView key) const { return operator()(murmur_hash_3(key)); }

    //! Return the value associated with the given key within the MPHF mapping
    size_t operator()(const std::string& key) const { return operator()(string_view_to_byte_view(key)); }

    /**
     * If RecSplitFeatures::kEnums (double_enum_index_) is enabled
     * Ordinal is an index of an item from the [0, key_count()) interval.
     * It is output of MPHF mapping, and input to the EF mapping:
     * - MPHF(key) = ordinal;
     * - EF(ordinal) = value (offset);
     * It can be converted to "data id" using base_data_id():
     *     data_id = base_data_id + ordinal
     *
     * If RecSplitFeatures::kEnums (double_enum_index_) is disabled
     * Ordinal is just the value (offset) output of MPHF mapping:
     * - MPHF(key) = value (offset) = ordinal;
     * In this case base_data_id() is not applicable.
     */
    struct Ordinal {
        uint64_t value{0};
    };

    //! Return the value associated with the given key within the index
    std::optional<Ordinal> lookup_ordinal_by_key(const std::string& key) const {
        return lookup_ordinal_by_key(string_view_to_byte_view(key));
    }

    //! Return the value associated with the given key within the index
    std::optional<Ordinal> lookup_ordinal_by_key(ByteView key) const {
        const Hash128& hashed_key{murmur_hash_3(key)};
        const auto record = operator()(hashed_key);
        const auto position = 1 + 8 + bytes_per_record_ * (record + 1);

        const auto region = encoded_file_->region();
        ensure(position + sizeof(uint64_t) < region.size(),
               [&]() { return "position: " + std::to_string(position) + " plus 8 exceeds file length"; });
        const auto value = endian::load_big_u64(region.data() + position) & record_mask_;

        if (less_false_positives_ && (value < existence_filter_.size()) &&
            (existence_filter_.at(value) != static_cast<uint8_t>(hashed_key.first))) {
            return std::nullopt;
        }

        return Ordinal{value};
    }

    //! Return the offset of the i-th element in the index. Perfect hash table lookup is not performed,
    //! only access to the Elias-Fano structure containing all offsets
    size_t lookup_by_ordinal(Ordinal ord) const {
        SILKWORM_ASSERT(double_enum_index_);
        return ef_offsets_->get(ord.value);
    }

    std::optional<uint64_t> lookup_data_id_by_key(ByteView key) const {
        SILKWORM_ASSERT(double_enum_index_);
        auto ord = lookup_ordinal_by_key(key);
        return ord ? std::optional{ord->value + base_data_id()} : std::nullopt;
    }

    std::optional<size_t> lookup_by_data_id(uint64_t data_id) const {
        // check if data_id is not out of range
        uint64_t min = base_data_id();
        uint64_t max = min + key_count() - 1;
        if ((data_id < min) || (data_id > max)) {
            return std::nullopt;
        }

        return lookup_by_ordinal(Ordinal{data_id - base_data_id()});
    }

    std::optional<size_t> lookup_by_key(ByteView key) const {
        auto ord = lookup_ordinal_by_key(key);
        if (!ord) return std::nullopt;
        return double_enum_index_ ? lookup_by_ordinal(*ord) : std::optional{ord->value};
    }

    //! Return the number of keys used to build the RecSplit instance
    size_t key_count() const { return key_count_; }

    bool empty() const { return key_count_ == 0; }
    uint64_t base_data_id() const { return base_data_id_; }
    uint64_t record_mask() const { return record_mask_; }
    uint64_t bucket_count() const { return bucket_count_; }
    uint16_t bucket_size() const { return bucket_size_; }

    bool double_enum_index() const { return double_enum_index_; }
    bool less_false_positives() const { return less_false_positives_; }

    //! Return the presence filter for the index. It can be empty if less false-positives feature is not enabled
    std::vector<uint8_t> existence_filter() const { return existence_filter_; }

    size_t file_size() const { return std::filesystem::file_size(index_path_); }

    std::filesystem::file_time_type last_write_time() const {
        return std::filesystem::last_write_time(index_path_);
    }

    MemoryMappedRegion memory_file_region() const { return encoded_file_ ? encoded_file_->region() : MemoryMappedRegion{}; }

  private:
    static size_t skip_bits(size_t m) { return kMemo[m] & 0xFFFF; }

    static size_t skip_nodes(size_t m) { return (kMemo[m] >> 16) & 0x7FF; }

    static uint64_t golomb_param(
        const size_t m,
        const std::array<uint32_t, kMaxBucketSize>& memo) {
        return memo[m] >> 27;
    }
    static uint64_t golomb_param_with_max_calculation(
        const size_t m,
        const std::array<uint32_t, kMaxBucketSize>& memo,
        uint16_t& golomb_param_max_index) {
        if (m > golomb_param_max_index) golomb_param_max_index = gsl::narrow<uint16_t>(m);
        return golomb_param(m, memo);
    }

    //! Generate the precomputed table of 32-bit values holding the Golomb-Rice code of a splitting (upper 5 bits),
    //! the number of nodes in the associated subtree (following 11 bits) and the sum of the Golomb-Rice code lengths
    //! in the same subtree (lower 16 bits)
    static constexpr void precompute_golomb_rice(const int m, std::array<uint32_t, kMaxBucketSize>* memo) {
        std::array<size_t, kMaxFanout> k{0};

        const auto [fanout, unit] = SplitStrategy::split_params(m);

        k[fanout - 1] = m;
        for (size_t i{0}; i < fanout - 1; ++i) {
            k[i] = unit;
            k[fanout - 1] -= k[i];
        }

        double sqrt_prod = 1;
        for (size_t i{0}; i < fanout; ++i) {
            sqrt_prod *= sqrt(k[i]);
        }

        const double p = sqrt(m) / (pow(2 * std::numbers::pi, (static_cast<double>(fanout) - 1.) * 0.5) * sqrt_prod);
        std::integral auto golomb_rice_length =
            math::int_ceil<uint32_t>(log2(-std::log((sqrt(5) + 1) * 0.5) / log1p(-p)));  // log2 Golomb modulus

        SILKWORM_ASSERT(golomb_rice_length <= 0x1F);  // Golomb-Rice code, stored in the 5 upper bits
        (*memo)[m] = golomb_rice_length << 27;
        for (size_t i{0}; i < fanout; ++i) {
            golomb_rice_length += (*memo)[k[i]] & 0xFFFF;
        }
        SILKWORM_ASSERT(golomb_rice_length <= 0xFFFF);  // Sum of Golomb-Rice code lengths in the subtree, stored in the lower 16 bits
        (*memo)[m] |= golomb_rice_length;

        uint32_t nodes = 1;
        for (size_t i{0}; i < fanout; ++i) {
            nodes += ((*memo)[k[i]] >> 16) & 0x7FF;
        }
        SILKWORM_ASSERT(LEAF_SIZE < 3 || nodes <= 0x7FF);  // Number of nodes in the subtree, stored in the middle 11 bits
        (*memo)[m] |= nodes << 16;
    }

    static constexpr std::array<uint32_t, kMaxBucketSize> fill_golomb_rice() {
        std::array<uint32_t, kMaxBucketSize> memo{0};
        size_t s{0};
        for (; s <= LEAF_SIZE; ++s) {
            memo[s] = kBijMemo[s] << 27 | (s > 1) << 16 | kBijMemo[s];
        }
        for (; s < kMaxBucketSize; ++s) {
            precompute_golomb_rice(static_cast<int>(s), &memo);
        }
        return memo;
    }

    //! Apply the RecSplit algorithm to the given bucket
    template <typename GRBuilder>
    static void recsplit(std::vector<uint64_t>& keys,
                         std::vector<uint64_t>& offsets,
                         std::vector<uint64_t>& buffer_keys,     // temporary buffer for keys
                         std::vector<uint64_t>& buffer_offsets,  // temporary buffer for offsets
                         GRBuilder& gr_builder,
                         std::ostream& index_ofs,
                         uint16_t& golomb_param_max_index,
                         uint8_t bytes_per_record) {
        recsplit(/*.level=*/0, keys, offsets, buffer_keys, buffer_offsets, /*.start=*/0, /*.end=*/keys.size(),
                 gr_builder, index_ofs, golomb_param_max_index, bytes_per_record);
    }

    template <typename GRBuilder>
    static void recsplit(int level,  // NOLINT
                         std::vector<uint64_t>& keys,
                         std::vector<uint64_t>& offsets,         // aka values
                         std::vector<uint64_t>& buffer_keys,     // temporary buffer for keys
                         std::vector<uint64_t>& buffer_offsets,  // temporary buffer for offsets
                         size_t start,
                         size_t end,
                         GRBuilder& gr_builder,
                         std::ostream& index_ofs,
                         uint16_t& golomb_param_max_index,
                         uint8_t bytes_per_record) {
        uint64_t salt = kStartSeed[level];
        const size_t m = end - start;
        SILKWORM_ASSERT(m > 1);
        if (m <= LEAF_SIZE) {
            // No need to build aggregation levels - just find bijection
            SILK_TRACE << "[index] recsplit level " << level << ", m=" << m << " < leaf size, just find bijection";
            if (level == 7) {
                SILK_TRACE << "[index] recsplit m: " << m << " salt: " << salt << " start: " << start << " bucket[start]=" << keys[start];
                for (size_t j = 0; j < m; ++j) {
                    SILK_TRACE << "[index] buffer m: " << m << " start: " << start << " j: " << j << " bucket[start + j]=" << keys[start + j];
                }
            }
            while (true) {
                uint32_t mask{0};
                bool fail{false};
                for (uint16_t i{0}; !fail && i < m; ++i) {
                    uint32_t bit = uint32_t{1} << remap16(remix(keys[start + i] + salt), m);
                    if ((mask & bit) != 0) {
                        fail = true;
                    } else {
                        mask |= bit;
                    }
                }
                if (!fail) break;
                ++salt;
            }
            for (size_t i{0}; i < m; ++i) {
                size_t j = remap16(remix(keys[start + i] + salt), m);
                buffer_offsets[j] = offsets[start + i];
            }
            Bytes uint64_buffer(8, '\0');
            for (size_t i{0}; i < m; ++i) {
                endian::store_big_u64(uint64_buffer.data(), buffer_offsets[i]);
                index_ofs.write(reinterpret_cast<const char*>(uint64_buffer.data() + (8 - bytes_per_record)), bytes_per_record);
                if (level == 0) {
                    SILK_TRACE << "[index] written offset: " << buffer_offsets[i];
                }
            }
            salt -= kStartSeed[level];
            const auto log2golomb = golomb_param_with_max_calculation(m, kMemo, golomb_param_max_index);
            gr_builder.append_fixed(salt, log2golomb);
            gr_builder.append_unary(static_cast<uint32_t>(salt >> log2golomb));
        } else {
            const auto [fanout, unit] = SplitStrategy::split_params(m);

            SILK_TRACE << "[index] recsplit level " << level << ", m=" << m << " > leaf size, fanout=" << fanout << " unit=" << unit;
            SILKWORM_ASSERT(fanout <= kLowerAggregationBound);

            std::vector<size_t> count(fanout, 0);  // temporary counters of key remapped occurrences
            while (true) {
                std::fill(count.begin(), count.end(), 0);
                for (size_t i{0}; i < m; ++i) {
                    ++count[static_cast<uint16_t>(remap16(remix(keys[start + i] + salt), m)) / unit];
                }
                bool broken{false};
                for (size_t i = 0; i < fanout - 1; ++i) {
                    broken = broken || (count[i] != unit);
                }
                if (!broken) break;
                ++salt;
            }
            for (size_t i{0}, c{0}; i < fanout; ++i, c += unit) {
                count[i] = c;
            }
            for (size_t i{0}; i < m; ++i) {
                auto j = static_cast<uint16_t>(remap16(remix(keys[start + i] + salt), m)) / unit;
                buffer_keys[count[j]] = keys[start + i];
                buffer_offsets[count[j]] = offsets[start + i];
                ++count[j];
            }
            std::copy(buffer_keys.data(), buffer_keys.data() + m, keys.data() + start);
            std::copy(buffer_offsets.data(), buffer_offsets.data() + m, offsets.data() + start);

            salt -= kStartSeed[level];
            const auto log2golomb = golomb_param_with_max_calculation(m, kMemo, golomb_param_max_index);
            gr_builder.append_fixed(salt, log2golomb);
            gr_builder.append_unary(static_cast<uint32_t>(salt >> log2golomb));

            size_t i{0};
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

    Hash128 murmur_hash_3(ByteView data) const {
        Hash128 h{};
        hasher_->hash_x64_128(data.data(), data.size(), &h);
        return h;
    }

    //! Maps a 128-bit to a bucket using the first 64-bit half
    uint64_t hash128_to_bucket(const Hash128& hash) const { return remap128(hash.first, bucket_count_); }

    void check_minimum_length(size_t minimum_length) {
        if (encoded_file_ && encoded_file_->size() < minimum_length) {
            throw std::runtime_error("index " + encoded_file_->path().filename().string() + " is too short: " +
                                     std::to_string(encoded_file_->size()) + " < " + std::to_string(minimum_length));
        }
    }

    void check_supported_features(RecSplitFeatures features) {
        for (const auto supported_feature : kSupportedFeatures) {
            features = features & ~supported_feature;
        }
        if (RecSplitFeatures{features} != RecSplitFeatures::kNone) {
            throw std::runtime_error("index " + encoded_file_->path().filename().string() + " has unsupported features: " +
                                     std::to_string(static_cast<uint8_t>(features)));
        }
    }

    friend std::ostream& operator<<(std::ostream& os, const RecSplit<LEAF_SIZE>& rs) {
        size_t leaf_size = LEAF_SIZE;
        os.write(reinterpret_cast<const char*>(&leaf_size), sizeof(leaf_size));
        os.write(reinterpret_cast<const char*>(&rs.bucket_size_), sizeof(rs.bucket_size_));
        os.write(reinterpret_cast<const char*>(&rs.key_count_), sizeof(rs.key_count_));
        os << rs.golomb_rice_codes_;
        os << rs.double_ef_index_;
        return os;
    }

    friend std::istream& operator>>(std::istream& is, RecSplit<LEAF_SIZE>& rs) {
        size_t leaf_size{0};
        is.read(reinterpret_cast<char*>(&leaf_size), sizeof(leaf_size));
        SILKWORM_ASSERT(leaf_size == LEAF_SIZE);
        is.read(reinterpret_cast<char*>(&rs.bucket_size_), sizeof(rs.bucket_size_));
        is.read(reinterpret_cast<char*>(&rs.key_count_), sizeof(rs.key_count_));
        rs.bucket_count_ = std::max(size_t{1}, (rs.key_count_ + rs.bucket_size_ - 1) / rs.bucket_size_);

        is >> rs.golomb_rice_codes_;
        is >> rs.double_ef_index_;
        return is;
    }

    static const size_t kLowerAggregationBound;

    static const size_t kUpperAggregationBound;

    //! The max index used in Golomb parameter array
    uint16_t golomb_param_max_index_{0};

    //! For each bucket size, the Golomb-Rice parameter (upper 8 bits) and the number of bits to
    //! skip in the fixed part of the tree (lower 24 bits).
    static const std::array<uint32_t, kMaxBucketSize> kMemo;

    //! The size in bytes of each Recsplit bucket (possibly except the last one)
    uint16_t bucket_size_;

    //! The number of keys for this Recsplit algorithm instance
    size_t key_count_;

    //! The number of buckets for this Recsplit algorithm instance
    size_t bucket_count_;

    //! The Golomb-Rice (GR) codes of splitting and bijection indices
    GolombRiceVector golomb_rice_codes_;

    //! Double Elias-Fano (EF) index for bucket cumulative keys and bit positions
    DoubleEliasFano double_ef_index_;

    //! Helper to encode the sequences of key offsets in the single EF code
    std::unique_ptr<EliasFano> ef_offsets_;

    //! Minimal app-specific ID of entries in this index - helps understanding what data stored in given shard - persistent field
    uint64_t base_data_id_;

    //! The path of the index file generated
    std::filesystem::path index_path_;

    //! Number of bytes used per index record
    uint8_t bytes_per_record_{0};

    //! The bitmask to be used to interpret record data
    uint64_t record_mask_{0};

    //! Flag indicating if two-level index "recsplit -> enum" + "enum -> offset" is enabled or not
    bool double_enum_index_{true};

    //! Flag indicating if less false-positives feature is enabled or not
    bool less_false_positives_{false};

    //! The 1-byte per key positional existence filter used to have less false-positives
    std::vector<uint8_t> existence_filter_;

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

inline constexpr size_t kLeafSize = 8;

using RecSplit8 = RecSplit<kLeafSize>;

template <>
const std::array<uint32_t, kMaxBucketSize> RecSplit8::kMemo;

using RecSplitIndex = RecSplit8;

}  // namespace silkworm::snapshots::rec_split

#pragma GCC diagnostic pop
