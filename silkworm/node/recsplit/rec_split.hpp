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

/* clang-format off */
#define _USE_MATH_DEFINES
#include <cmath>
#if !defined(M_PI) && defined(_MSC_VER)
#include <corecrt_math_defines.h>
#endif
/* clang-format on */

#include <array>
#include <bit>
#include <cassert>
#include <chrono>
#include <execution>
#include <fstream>
#include <limits>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <gsl/util>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/memory_mapped_file.hpp>
#include <silkworm/infra/concurrency/thread_pool.hpp>
#include <silkworm/node/etl/collector.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#if defined(__clang__)
#pragma GCC diagnostic ignored "-Winvalid-constexpr"
#endif /* defined(__clang__) */
#pragma GCC diagnostic ignored "-Wsign-compare"

#include <silkworm/node/recsplit/encoding/elias_fano.hpp>
#include <silkworm/node/recsplit/encoding/golomb_rice.hpp>
#include <silkworm/node/recsplit/support/murmur_hash3.hpp>

// prettyPrint a vector, used for debugging
// usage: prettyPrint(vi);
// usage: prettyPrint(vi, "{", ", ", "}");
template <typename T>
std::string prettyPrint(const std::vector<T>& v, const std::string& prefix = "[", const std::string& separator = ", ", const std::string& suffix = "]") {
    std::ostringstream oss;
    oss << prefix;
    for (size_t i = 0; i < v.size(); ++i) {
        oss << v[i];
        if (i < v.size() - 1) {
            oss << separator;
        }
    }
    oss << suffix;
    return oss.str();
}

// Check if the vector contains duplicates without altering the original vector order
// Used here to check the keys vector (whose elements are related to the element of values vector at the same index)
template <typename T>
bool containsDuplicate(const std::vector<T>& items) {
    // Create an index vector
    std::vector<int> indices(items.size());
    for (size_t i = 0; i < items.size(); ++i) {
        indices[i] = i;
    }

    // Sort the index vector based on the items
    std::sort(indices.begin(), indices.end(),
              [&items](int i1, int i2) { return items[i1] < items[i2]; });

    // Check for duplicates using the sorted index vector
    for (size_t i = 1; i < indices.size(); ++i) {
        if (items[indices[i]] == items[indices[i - 1]]) {
            return true;
        }
    }

    return false;  // No duplicate found
}

template <typename T>
void set_max(std::atomic<T>& atom, T v) {
    T current = atom.load();
    while (v > current && !atom.compare_exchange_weak(current, v));
}

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
    static inline const std::size_t kLowerAggregationBound = LEAF_SIZE * max(2, ceil(0.35 * LEAF_SIZE + 1. / 2));

    //! The lower bound for secondary (upper) key aggregation
    static inline const std::size_t kUpperAggregationBound = kLowerAggregationBound * (LEAF_SIZE < 7 ? 2 : ceil(0.21 * LEAF_SIZE + 9. / 10));

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
    std::size_t keys_count;                                 // The total number of keys in the RecSplit
    std::size_t bucket_size;                                // The number of keys in each bucket (except probably last one)
    std::filesystem::path index_path;                       // The path of the generated RecSplit index file
    uint64_t base_data_id;                                  // Application-specific base data ID written in index header
    bool double_enum_index{true};                           // Flag indicating if 2-level index is required
    std::size_t etl_optimal_size{etl::kOptimalBufferSize};  // Optimal size for offset and bucket ETL collectors
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

    struct Bucket {
        Bucket(uint64_t bucket_id, std::size_t bucket_size) : bucket_id_{bucket_id}, mutex_{new std::mutex} {
            keys_.reserve(bucket_size);
            values_.reserve(bucket_size);
        }
        Bucket(const Bucket&) = delete;
        Bucket(Bucket&& other) noexcept : bucket_id_{other.bucket_id_}, keys_{std::move(other.keys_)}, values_{std::move(other.values_)}, gr_builder_{std::move(other.gr_builder_)}, mutex_{other.mutex_} {
            other.mutex_ = nullptr;
        }
        ~Bucket() {
            delete mutex_;
        }

        //! Identifier of the current bucket being accumulated
        uint64_t bucket_id_{0};

        //! 64-bit fingerprints of keys in the current bucket accumulated before the recsplit is performed for that bucket
        std::vector<uint64_t> keys_;

        //! Index offsets for the current bucket
        std::vector<uint64_t> values_;

        //! Helper to build GR codes of splitting and bijection indices, local to current bucket
        GolombRiceVector::LazyBuilder gr_builder_;

        //!
        std::mutex* mutex_;

        //! The local max index used in Golomb parameter array
        uint16_t golomb_param_max_index_{0};

        //! Helper index output stream
        std::stringstream index_ofs{std::ios::in | std::ios::out | std::ios::binary};

        void clear() {
            // bucket_id_ = 0;
            keys_.clear();
            values_.clear();
            gr_builder_.clear();
            index_ofs.clear();
        }
    };

    explicit RecSplit(const RecSplitSettings& settings, uint32_t salt = 0)
        : bucket_size_(settings.bucket_size),
          key_count_(settings.keys_count),
          bucket_count_((key_count_ + bucket_size_ - 1) / bucket_size_),
          base_data_id_(settings.base_data_id),
          index_path_(settings.index_path),
          double_enum_index_(settings.double_enum_index) {
        // Generate random salt for murmur3 hash
        std::random_device rand_dev;
        std::mt19937 rand_gen32{rand_dev()};
        salt_ = salt != 0 ? salt : rand_gen32();
        hasher_ = std::make_unique<Murmur3>(salt_);
        // Prepare backets
        buckets_.reserve(bucket_count_);
        for (int i = 0; i < bucket_count_; i++)
            buckets_.emplace_back(i, bucket_size_);
        if (double_enum_index_)
            offsets_.reserve(key_count_);
    }

    explicit RecSplit(std::filesystem::path index_path, std::optional<MemoryMappedRegion> index_region = {})
        : index_path_{index_path},
          encoded_file_{std::make_optional<MemoryMappedFile>(std::move(index_path), std::move(index_region))} {
        SILK_DEBUG << "RecSplit encoded file path: " << encoded_file_->path();
        check_minimum_length(kFirstMetadataHeaderLength);

        const auto address = encoded_file_->address();

        encoded_file_->advise_sequential();

        // Read fixed metadata header fields from RecSplit-encoded file
        base_data_id_ = endian::load_big_u64(address);
        key_count_ = endian::load_big_u64(address + kBaseDataIdLength);
        bytes_per_record_ = address[kBaseDataIdLength + kKeyCountLength];
        record_mask_ = (uint64_t(1) << (8 * bytes_per_record_)) - 1;
        SILK_DEBUG << "Base data ID: " << base_data_id_ << " key count: " << key_count_
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

        const uint16_t primary_aggr_bound = leaf_size * succinct::max(2, std::ceil(0.35 * leaf_size + 1. / 2));
        SILKWORM_ASSERT(primary_aggr_bound == kLowerAggregationBound);
        const uint16_t secondary_aggr_bound = primary_aggr_bound * (leaf_size < 7 ? 2 : ceil(0.21 * leaf_size + 9. / 10));
        SILKWORM_ASSERT(secondary_aggr_bound == kUpperAggregationBound);

        // Read salt
        salt_ = endian::load_big_u32(address + offset);
        offset += kSaltSizeLength;
        hasher_ = std::make_unique<Murmur3>(salt_);

        // Read start seed
        const uint8_t start_seed_length = (address + offset)[0];
        offset += kStartSeedSizeLength;
        SILKWORM_ASSERT(start_seed_length == kStartSeed.size());
        check_minimum_length(offset + start_seed_length * sizeof(uint64_t));
        std::array<uint64_t, kStartSeed.size()> start_seed;
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

    void add_key(const hash128_t& key_hash, uint64_t offset, uint64_t ordinal) {
        if (built_) {
            throw std::logic_error{"cannot add key after perfect hash function has been built"};
        }

        if (keys_added_ % 100'000 == 0) {
            SILK_DEBUG << "[index] add key hash: first=" << key_hash.first << " second=" << key_hash.second << " offset=" << offset;
        }

        uint64_t bucket_id = hash128_to_bucket(key_hash);
        auto bucket_key = key_hash.second;

        set_max(max_offset_, offset);

        ensure(bucket_id < bucket_count_, "bucket_id out of range");
        Bucket& bucket = buckets_[bucket_id];

        if (double_enum_index_) {
            std::lock_guard<std::mutex> lock{*bucket.mutex_};
            offsets_.push_back(offset);

            bucket.keys_.emplace_back(bucket_key);
            bucket.values_.emplace_back(ordinal);
        } else {
            std::lock_guard<std::mutex> lock{*bucket.mutex_};
            bucket.keys_.emplace_back(bucket_key);
            bucket.values_.emplace_back(offset);
        }

        keys_added_++;
    }

    void add_key(const void* key_data, const size_t key_length, uint64_t offset) {
        uint64_t ordinal = keys_added_;
        add_key(key_data, key_length, offset, ordinal);
    }

    void add_key(const void* key_data, const size_t key_length, uint64_t offset, uint64_t ordinal) {
        if (built_) {
            throw std::logic_error{"cannot add key after perfect hash function has been built"};
        }

        if (keys_added_ % 100'000 == 0) {
            SILK_DEBUG << "[index] add key: " << to_hex(ByteView{reinterpret_cast<const uint8_t*>(key_data), key_length});
        }

        const auto key_hash = murmur_hash_3(key_data, key_length);
        add_key(key_hash, offset, ordinal);
    }

    void add_key(const std::string& key, uint64_t offset) {
        add_key(key.c_str(), key.size(), offset);
    }

    [[nodiscard]] bool build() {  // for test
        ThreadPool thread_pool{std::thread::hardware_concurrency()};
        return build(thread_pool);
    }
    //! Build the MPHF using the RecSplit algorithm and save the resulting index file
    //! \warning duplicate keys will cause this method to never return
    [[nodiscard]] bool build(ThreadPool& thread_pool) {
        if (built_) {
            throw std::logic_error{"perfect hash function already built"};
        }
        if (keys_added_ != key_count_) {
            throw std::logic_error{"keys expected: " + std::to_string(key_count_) + " added: " + std::to_string(keys_added_)};
        }
        const auto tmp_index_path{std::filesystem::path{index_path_}.concat(".tmp")};
        std::ofstream index_output_stream{tmp_index_path, std::ios::binary};
        SILK_DEBUG << "[index] creating temporary index file: " << tmp_index_path.string();

        // Write minimal app-specific data ID in the index file
        Bytes uint64_buffer(8, '\0');
        endian::store_big_u64(uint64_buffer.data(), base_data_id_);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
        SILK_DEBUG << "[index] written base data ID: " << base_data_id_;

        // Write number of keys
        endian::store_big_u64(uint64_buffer.data(), keys_added_);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
        SILK_DEBUG << "[index] written number of keys: " << keys_added_;

        // Write number of bytes per index record
        bytes_per_record_ = (std::bit_width(max_offset_.load()) + 7) / 8;
        index_output_stream.write(reinterpret_cast<const char*>(&bytes_per_record_), sizeof(uint8_t));
        SILK_DEBUG << "[index] written bytes per record: " << int(bytes_per_record_);
        SILK_TRACE << "[index] calculating file=" << index_path_.string();

        // SILK_INFO << "par-ver - GEN - Base data ID: " << base_data_id_ << " key count: " << key_count_
        //          << " keys_added: " << keys_added_ << " bytes per record: " << int(bytes_per_record_)
        //          << " record mask: " << record_mask_ << " max_hoffset: " << max_offset_ << " bucket_count: " << bucket_count_;

        // Find splitting trees for each bucket
        std::atomic_bool collision{false};
        for (auto& bucket : buckets_) {
            thread_pool.push_task([&]() noexcept(false) {
                if (collision) return;  // skip work if collision detected
                bool local_collision = recsplit_bucket(bucket, bytes_per_record_);
                if (local_collision) collision = true;
                // SILK_INFO << "processed " << bucket.bucket_id_;
            });
        }
        thread_pool.wait_for_tasks();
        if (collision) {
            SILK_WARN << "[index] collision detected";
            return true;
        }

        // Store prefix sums of bucket sizes and bit positions
        std::vector<int64_t> bucket_size_accumulator_(bucket_count_ + 1);      // accumulator for size of every bucket
        std::vector<int64_t> bucket_position_accumulator_(bucket_count_ + 1);  // accumulator for position of every bucket in the encoding of the hash function

        bucket_size_accumulator_[0] = bucket_position_accumulator_[0] = 0;
        for (size_t i = 0; i < bucket_count_; i++) {
            bucket_size_accumulator_[i + 1] = bucket_size_accumulator_[i] + buckets_[i].keys_.size();

            // auto* underlying_buffer = buckets_[i].index_ofs.rdbuf();
            // if (!is_empty(underlying_buffer))
            //     index_output_stream << underlying_buffer;
            char byte;
            while (buckets_[i].index_ofs.get(byte)) {  // todo(mike): avoid this, use a buffer in place of index_ofs
                index_output_stream.put(byte);
            }
            // index_output_stream << buckets_[i].index_ofs.rdbuf();  // todo(mike): better but fails when rdbuf() is empty

            if (buckets_[i].keys_.size() > 1) {
                buckets_[i].gr_builder_.append_to(gr_builder_);
            }

            bucket_position_accumulator_[i + 1] = gr_builder_.get_bits();

            SILKWORM_ASSERT(bucket_size_accumulator_[i + 1] >= bucket_size_accumulator_[i]);
            SILKWORM_ASSERT(bucket_position_accumulator_[i + 1] >= bucket_position_accumulator_[i]);

            golomb_param_max_index_ = std::max(golomb_param_max_index_, buckets_[i].golomb_param_max_index_);
        }

        gr_builder_.append_fixed(1, 1);  // Sentinel (avoids checking for parts of size 1)

        // SILK_INFO << "PROBE par-vers - sizes: " << prettyPrint(bucket_size_accumulator_);
        // SILK_INFO << "PROBE par-vers - positions: " << prettyPrint(bucket_position_accumulator_);

        // Concatenate the representation of each bucket
        golomb_rice_codes_ = gr_builder_.build();

        // SILK_INFO << "PROBE par-vers - golomb_rice_codes: size " << golomb_rice_codes_.size() << ", content " << golomb_rice_codes_;

        // Build Elias-Fano index for offsets (if any)
        if (double_enum_index_) {
            std::sort(offsets_.begin(), offsets_.end());
            ef_offsets_ = std::make_unique<EliasFano>(keys_added_, max_offset_);
            for (auto offset : offsets_) {
                ef_offsets_->add_offset(offset);
            }
            ef_offsets_->build();
        }

        // Construct double Elias-Fano index for bucket cumulative keys and bit positions
        std::vector<uint64_t> cumulative_keys{bucket_size_accumulator_.begin(), bucket_size_accumulator_.end()};
        std::vector<uint64_t> positions(bucket_position_accumulator_.begin(), bucket_position_accumulator_.end());
        double_ef_index_.build(cumulative_keys, positions);

        built_ = true;

        // SILK_INFO << "par-vers: written bytes so far " << index_output_stream.tellp();

        // Write out bucket count, bucket size, leaf size
        endian::store_big_u64(uint64_buffer.data(), bucket_count_);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
        SILK_DEBUG << "[index] written bucket count: " << bucket_count_;

        endian::store_big_u16(uint64_buffer.data(), bucket_size_);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint16_t));
        SILK_DEBUG << "[index] written bucket size: " << bucket_size_;

        endian::store_big_u16(uint64_buffer.data(), LEAF_SIZE);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint16_t));
        SILK_DEBUG << "[index] written leaf size: " << LEAF_SIZE;

        // Write out salt
        endian::store_big_u32(uint64_buffer.data(), salt_);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint32_t));
        SILK_DEBUG << "[index] written murmur3 salt: " << salt_ << " [" << to_hex(uint64_buffer) << "]";

        // Write out start seeds
        constexpr uint8_t start_seed_length = kStartSeed.size();
        index_output_stream.write(reinterpret_cast<const char*>(&start_seed_length), sizeof(uint8_t));
        SILK_DEBUG << "[index] written start seed length: " << int(start_seed_length);

        for (const uint64_t s : kStartSeed) {
            endian::store_big_u64(uint64_buffer.data(), s);
            index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
        }
        SILK_DEBUG << "[index] written start seed: first=" << kStartSeed[0] << " last=" << kStartSeed[kStartSeed.size() - 1];

        // Write out index flag
        const uint8_t enum_index_flag = double_enum_index_ ? 1 : 0;
        index_output_stream.write(reinterpret_cast<const char*>(&enum_index_flag), sizeof(uint8_t));

        // Write out Elias-Fano code for offsets (if any)
        if (double_enum_index_) {
            index_output_stream << *ef_offsets_;
            SILK_DEBUG << "[index] written EF code for offsets [size: " << ef_offsets_->count() - 1 << "]";
        }

        // Write out the number of Golomb-Rice codes used i.e. the max index used plus one
        endian::store_big_u16(uint64_buffer.data(), golomb_param_max_index_ + 1);
        // Erigon writes 4-instead-of-2 bytes here: 2 spurious come from previous buffer content, i.e. last seed value
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint32_t));
        SILK_DEBUG << "[index] written GR params count: " << golomb_param_max_index_ + 1 << " code size: " << golomb_rice_codes_.size();

        // Write out Golomb-Rice code
        index_output_stream << golomb_rice_codes_;

        // Write out Elias-Fano code for bucket cumulative keys and bit positions
        index_output_stream << double_ef_index_;

        index_output_stream.close();

        SILK_DEBUG << "[index] renaming " << tmp_index_path.string() << " as " << index_path_.string();
        std::filesystem::rename(tmp_index_path, index_path_);

        return false;
    }

    void reset_new_salt() {
        built_ = false;
        keys_added_ = 0;
        offsets_.clear();
        max_offset_ = 0;
        for (auto& bucket : buckets_) {
            bucket.clear();
        }
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
        uint64_t cum_keys, cum_keys_next, bit_pos;
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
    std::size_t lookup(ByteView key) const { return lookup(key.data(), key.size()); }

    //! Return the value associated with the given key within the index
    std::size_t lookup(const std::string& key) const { return lookup(key.data(), key.size()); }

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
    std::size_t ordinal_lookup(uint64_t i) const { return ef_offsets_->get(i); }

    //! Return the number of keys used to build the RecSplit instance
    std::size_t key_count() const { return key_count_; }

    bool empty() const { return key_count_ == 0; }
    uint64_t base_data_id() const { return base_data_id_; }
    uint64_t record_mask() const { return record_mask_; }
    uint64_t bucket_count() const { return bucket_count_; }
    uint16_t bucket_size() const { return bucket_size_; }

    std::size_t file_size() const { return std::filesystem::file_size(index_path_); }

    std::filesystem::file_time_type last_write_time() const {
        return std::filesystem::last_write_time(index_path_);
    }

    uint8_t* memory_file_address() const { return encoded_file_ ? encoded_file_->address() : nullptr; }
    std::size_t memory_file_size() const { return encoded_file_ ? encoded_file_->length() : 0; }

  private:
    static inline std::size_t skip_bits(std::size_t m) { return memo[m] & 0xFFFF; }

    static inline std::size_t skip_nodes(std::size_t m) { return (memo[m] >> 16) & 0x7FF; }

    static constexpr uint64_t golomb_param(const std::size_t m,
                                           const std::array<uint32_t, kMaxBucketSize>& memo,
                                           uint16_t& golomb_param_max_index) {
        if (m > golomb_param_max_index) golomb_param_max_index = m;
        return memo[m] >> 27;
    }
    static constexpr uint64_t golomb_param(const std::size_t m,
                                           const std::array<uint32_t, kMaxBucketSize>& memo) {
        return memo[m] >> 27;
    }

    // Generates the precomputed table of 32-bit values holding the Golomb-Rice code
    // of a splitting (upper 5 bits), the number of nodes in the associated subtree
    // (following 11 bits) and the sum of the Golomb-Rice code lengths in the same
    // subtree (lower 16 bits).
    static constexpr void precompute_golomb_rice(const int m, std::array<uint32_t, kMaxBucketSize>* memo) {
        std::array<std::size_t, kMaxFanout> k{0};

        const auto [fanout, unit] = SplittingStrategy<LEAF_SIZE>::split_params(m);

        k[fanout - 1] = m;
        for (std::size_t i{0}; i < fanout - 1; ++i) {
            k[i] = unit;
            k[fanout - 1] -= k[i];
        }

        double sqrt_prod = 1;
        for (std::size_t i{0}; i < fanout; ++i) {
            sqrt_prod *= sqrt(k[i]);
        }

        const double p = sqrt(m) / (pow(2 * M_PI, (fanout - 1.) / 2) * sqrt_prod);
        auto golomb_rice_length = static_cast<uint32_t>(ceil(log2(-std::log((sqrt(5) + 1) / 2) / log1p(-p))));  // log2 Golomb modulus

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

    //! Compute and store the splittings and bijections of the current bucket
    // It would be better to make this function a member of Bucket
    static bool recsplit_bucket(Bucket& bucket, uint8_t bytes_per_record) {
        // Sets of size 0 and 1 are not further processed, just write them to index
        if (bucket.keys_.size() > 1) {
            if (containsDuplicate(bucket.keys_)) {
                SILK_ERROR << "collision detected";
                return true;
            }

            std::vector<uint64_t> buffer_keys;     // temporary buffer for keys
            std::vector<uint64_t> buffer_offsets;  // temporary buffer for offsets
            buffer_keys.resize(bucket.keys_.size());
            buffer_offsets.resize(bucket.values_.size());

            recsplit(bucket.keys_, bucket.values_, buffer_keys, buffer_offsets, bucket.gr_builder_,
                     bucket.index_ofs, bucket.golomb_param_max_index_, bytes_per_record);

        } else {
            for (const auto offset : bucket.values_) {
                Bytes uint64_buffer(8, '\0');
                endian::store_big_u64(uint64_buffer.data(), offset);
                bucket.index_ofs.write(reinterpret_cast<const char*>(uint64_buffer.data()), 8);
                SILK_DEBUG << "[index] written offset: " << offset;
            }
        }

        return false;
    }

    //! Apply the RecSplit algorithm to the given bucket
    static void recsplit(std::vector<uint64_t>& keys,
                         std::vector<uint64_t>& offsets,
                         std::vector<uint64_t>& buffer_keys,     // temporary buffer for keys
                         std::vector<uint64_t>& buffer_offsets,  // temporary buffer for offsets
                         GolombRiceVector::LazyBuilder& gr_builder,
                         std::ostream& index_ofs,
                         uint16_t& golomb_param_max_index,
                         uint8_t bytes_per_record) {
        // SILK_INFO << "PROBE par-vers - keys: " << prettyPrint(keys);
        // SILK_INFO << "PROBE par-vers - offsets: " << prettyPrint(offsets);
        // SILK_INFO << "PROBE par-vers - buffer_keys_: " << prettyPrint(buffer_keys_);
        // SILK_INFO << "PROBE par-vers - buffer_offsets_: " << prettyPrint(buffer_offsets_);

        recsplit(/*.level=*/0, keys, offsets, buffer_keys, buffer_offsets, /*.start=*/0, /*.end=*/keys.size(),
                 gr_builder, index_ofs, golomb_param_max_index, bytes_per_record);
    }

    static void recsplit(int level,
                         std::vector<uint64_t>& keys,
                         std::vector<uint64_t>& offsets,         // aka values
                         std::vector<uint64_t>& buffer_keys,     // temporary buffer for keys
                         std::vector<uint64_t>& buffer_offsets,  // temporary buffer for offsets
                         std::size_t start,
                         std::size_t end,
                         GolombRiceVector::LazyBuilder& gr_builder,
                         std::ostream& index_ofs,
                         uint16_t& golomb_param_max_index,
                         uint8_t bytes_per_record) {
        uint64_t salt = kStartSeed[level];
        const uint16_t m = end - start;
        SILKWORM_ASSERT(m > 1);
        if (m <= LEAF_SIZE) {
            // No need to build aggregation levels - just find bijection
            // SILK_INFO << "PROBE [index] recsplit level " << level << ", m=" << m << " < leaf size, just find bijection";
            // if (level == 7) {
            //    SILK_DEBUG << "[index] recsplit m: " << m << " salt: " << salt << " start: " << start << " bucket[start]=" << bucket[start]
            //               << " current_bucket_id_=" << current_bucket_id_;
            //    for (std::size_t j = 0; j < m; j++) {
            //        SILK_DEBUG << "[index] buffer m: " << m << " start: " << start << " j: " << j << " bucket[start + j]=" << bucket[start + j];
            //    }
            // }
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
            Bytes uint64_buffer(8, '\0');  // todo(mike): do we need this?
            for (auto i{0}; i < m; i++) {
                endian::store_big_u64(uint64_buffer.data(), buffer_offsets[i]);
                index_ofs.write(reinterpret_cast<const char*>(uint64_buffer.data() + (8 - bytes_per_record)), bytes_per_record);
                // if (level == 0) {
                //     SILK_DEBUG << "[index] written offset: " << buffer_offsets_[i];
                // }
            }
            salt -= kStartSeed[level];
            const auto log2golomb = golomb_param(m, memo, golomb_param_max_index);
            gr_builder.append_fixed(salt, log2golomb);
            gr_builder.append_unary(static_cast<uint32_t>(salt >> log2golomb));
        } else {
            const auto [fanout, unit] = SplitStrategy::split_params(m);

            // SILK_INFO << "PROBE [index] recsplit level " << level << ", m=" << m << " > leaf size, fanout=" << fanout << " unit=" << unit;
            // SILK_DEBUG << "[index] m > _leaf: m=" << m << " fanout=" << fanout << " unit=" << unit;
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
            const auto log2golomb = golomb_param(m, memo);
            gr_builder.append_fixed(salt, log2golomb);
            gr_builder.append_unary(static_cast<uint32_t>(salt >> log2golomb));

            std::size_t i;
            for (i = 0; i < m - unit; i += unit) {
                recsplit(level + 1, keys, offsets, buffer_keys, buffer_offsets, start + i, start + i + unit, gr_builder, index_ofs, golomb_param_max_index, bytes_per_record);
            }
            if (m - i > 1) {
                recsplit(level + 1, keys, offsets, buffer_keys, buffer_offsets, start + i, end, gr_builder, index_ofs, golomb_param_max_index, bytes_per_record);
            } else if (m - i == 1) {
                Bytes uint64_buffer(8, '\0');
                endian::store_big_u64(uint64_buffer.data(), offsets[start + i]);
                index_ofs.write(reinterpret_cast<const char*>(uint64_buffer.data() + (8 - bytes_per_record)), bytes_per_record);
                // if (level == 0) {
                //    SILK_DEBUG << "[index] written offset: " << offsets[start + i];
                // }
            }
        }
    }

    hash128_t inline murmur_hash_3(const void* data, const size_t length) const {
        hash128_t h{};
        hasher_->hash_x64_128(data, length, &h);
        return h;
    }

    // Maps a 128-bit to a bucket using the first 64-bit half.
    inline uint64_t hash128_to_bucket(const hash128_t& hash) const { return remap128(hash.first, bucket_count_); }

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
        size_t leaf_size;
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
    std::size_t bucket_size_;

    //! The number of keys for this Recsplit algorithm instance
    std::size_t key_count_;

    //! The number of buckets for this Recsplit algorithm instance
    std::size_t bucket_count_;

    //! The Golomb-Rice (GR) codes of splitting and bijection indices
    GolombRiceVector golomb_rice_codes_;

    //! Helper to build GR codes of splitting and bijection indices
    GolombRiceBuilder gr_builder_;

    //! Double Elias-Fano (EF) index for bucket cumulative keys and bit positions
    DoubleEliasFano double_ef_index_;

    //! Helper to encode the sequences of key offsets in the single EF code
    std::unique_ptr<EliasFano> ef_offsets_;

    //! Minimal app-specific ID of entries of this index - helps app understand what data stored in given shard - persistent field
    uint64_t base_data_id_;

    //! The path of the index file generated
    std::filesystem::path index_path_;

    //! The number of keys currently added
    std::atomic<uint64_t> keys_added_{0};

    //! Minimum delta for Elias-Fano encoding of "enum -> offset" index
    // uint64_t min_delta_{0};  // unused

    //! Last previously added offset (for calculating minimum delta for Elias-Fano encoding of "enum -> offset" index)
    // uint64_t previous_offset_{0};  // unused

    //! Maximum value of offset used to decide how many bytes to use for Elias-Fano encoding
    std::atomic<uint64_t> max_offset_{0};

    //! Number of bytes used per index record
    uint8_t bytes_per_record_{0};

    //! The bitmask to be used to interpret record data
    uint64_t record_mask_{0};

    //! The buckets of the RecSplit algorithm
    std::vector<Bucket> buckets_;

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
};

constexpr std::size_t kLeafSize{8};
using RecSplit8 = RecSplit<kLeafSize>;

template <>
const std::array<uint32_t, kMaxBucketSize> RecSplit8::memo;

using RecSplitIndex = RecSplit8;

}  // namespace silkworm::succinct

#pragma GCC diagnostic pop
