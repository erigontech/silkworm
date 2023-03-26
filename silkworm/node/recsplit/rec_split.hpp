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
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/etl/collector.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#if defined(__clang__)
#pragma GCC diagnostic ignored "-Winvalid-constexpr"
#endif /* defined(__clang__) */
#pragma GCC diagnostic ignored "-Wsign-compare"

#include <silkworm/node/recsplit/encoding/elias_fano.hpp>
#include <silkworm/node/recsplit/encoding/golomb_rice.hpp>
#include <silkworm/node/recsplit/support/murmur_hash3.hpp>

namespace silkworm::succinct {

using namespace std::chrono;

//! Assumed *maximum* size of a bucket. Works with high probability up to average bucket size ~2000
static const int kMaxBucketSize = 3000;

//! Assumed *maximum* size of splitting tree leaves
static const int kMaxLeafSize = 24;

//! Assumed *maximum* size of splitting tree fanout
static const int kMaxFanout = 32;

//! Starting seed at given distance from the root (extracted at random)
static constexpr uint64_t kStartSeed[] = {
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
template <size_t LEAF_SIZE>
class RecSplit {
  public:
    using SplitStrategy = SplittingStrategy<LEAF_SIZE>;
    using GolombRiceBuilder = typename GolombRiceVector::Builder;
    using EliasFano = EliasFanoList32;
    using DoubleEliasFano = DoubleEliasFanoList16;

    explicit RecSplit(const RecSplitSettings& settings, uint32_t salt = 0)
        : bucket_size_(settings.bucket_size),
          key_count_(settings.keys_count),
          bucket_count_((key_count_ + bucket_size_ - 1) / bucket_size_),
          base_data_id_(settings.base_data_id),
          index_path_(settings.index_path),
          double_enum_index_(settings.double_enum_index),
          offset_collector_(settings.etl_optimal_size),
          bucket_collector_(settings.etl_optimal_size) {
        bucket_size_accumulator_.reserve(bucket_count_ + 1);
        bucket_position_accumulator_.reserve(bucket_count_ + 1);
        bucket_size_accumulator_.resize(1);      // Start with 0 as bucket accumulated size
        bucket_position_accumulator_.resize(1);  // Start with 0 as bucket accumulated position
        current_bucket_.reserve(bucket_size_);
        current_bucket_offsets_.reserve(bucket_size_);
        count_.reserve(kLowerAggregationBound);

        // Generate random salt for murmur3 hash
        std::random_device rand_dev;
        std::mt19937 rand_gen32{rand_dev()};
        salt_ = salt != 0 ? salt : rand_gen32();
        hasher_ = std::make_unique<Murmur3>(salt_);
    }

    void add_key(const hash128_t& key_hash, uint64_t offset) {
        if (built_) {
            throw std::logic_error{"cannot add key after perfect hash function has been built"};
        }

        if (keys_added_ % 100'000 == 0) {
            SILK_DEBUG << "[index] add key hash: first=" << key_hash.first << " second=" << key_hash.second << " offset=" << offset;
        }

        Bytes bucket_key(16, '\0');
        endian::store_big_u64(bucket_key.data(), hash128_to_bucket(key_hash));
        endian::store_big_u64(bucket_key.data() + sizeof(uint64_t), key_hash.second);
        Bytes offset_key(8, '\0');
        endian::store_big_u64(offset_key.data(), offset);

        if (offset > max_offset_) {
            max_offset_ = offset;
        }
        if (keys_added_ > 0) {
            const auto delta = offset - previous_offset_;
            if (keys_added_ == 1 || delta < min_delta_) {
                min_delta_ = delta;
            }
        }

        if (double_enum_index_) {
            offset_collector_.collect({offset_key, {}});

            Bytes current_key_count(8, '\0');
            endian::store_big_u64(current_key_count.data(), keys_added_);
            bucket_collector_.collect({bucket_key, current_key_count});
        } else {
            bucket_collector_.collect({bucket_key, offset_key});
        }
        keys_added_++;
        previous_offset_ = offset;
    }

    void add_key(const void* key_data, const size_t key_length, uint64_t offset) {
        if (built_) {
            throw std::logic_error{"cannot add key after perfect hash function has been built"};
        }

        if (keys_added_ % 100'000 == 0) {
            SILK_DEBUG << "[index] add key: " << to_hex(ByteView{reinterpret_cast<const uint8_t*>(key_data), key_length});
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
        bytes_per_record_ = (std::bit_width(max_offset_) + 7) / 8;
        index_output_stream.write(reinterpret_cast<const char*>(&bytes_per_record_), sizeof(uint8_t));
        SILK_DEBUG << "[index] written bytes per record: " << int(bytes_per_record_);

        current_bucket_id_ = std::numeric_limits<uint64_t>::max();  // To make sure 0 bucket is detected

        auto bucket_collector_clear = gsl::finally([&]() { bucket_collector_.clear(); });
        SILK_INFO << "[index] calculating file=" << index_path_.string();

        // We use an exception for collision error condition because ETL currently does not support loading errors
        // TODO(canepat) refactor ETL to support errors in LoadFunc and propagate them to caller to get rid of CollisionError
        struct CollisionError : public std::runtime_error {
            explicit CollisionError(uint64_t _bucket_id) : runtime_error("collision"), bucket_id(_bucket_id) {}
            uint64_t bucket_id;
        };
        try {
            // Passing a void cursor is valid case for ETL when DB modification is not expected
            db::PooledCursor empty_cursor{};
            bucket_collector_.load(empty_cursor, [&](const etl::Entry& entry, auto&, MDBX_put_flags_t) {
                // k is the big-endian encoding of the bucket number and the v is the key that is assigned into that bucket
                const uint64_t bucket_id = endian::load_big_u64(entry.key.data());
                SILK_TRACE << "[index] processing bucket_id=" << bucket_id;
                if (current_bucket_id_ != bucket_id) {
                    if (current_bucket_id_ != std::numeric_limits<uint64_t>::max()) {
                        bool collision = recsplit_current_bucket(index_output_stream);
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
            bool collision_detected = recsplit_current_bucket(index_output_stream);
            if (collision_detected) return true;
        }
        gr_builder_.append_fixed(1, 1);  // Sentinel (avoids checking for parts of size 1)
        golomb_rice_codes_ = gr_builder_.build();

        // Build Elias-Fano index for offsets (if any)
        if (double_enum_index_) {
            ef_offsets_ = std::make_unique<EliasFano>(keys_added_, max_offset_);
            db::PooledCursor empty_cursor{};
            offset_collector_.load(empty_cursor, [&](const etl::Entry& entry, auto&, MDBX_put_flags_t) {
                const uint64_t offset = endian::load_big_u64(entry.key.data());
                ef_offsets_->add_offset(offset);
            });
            ef_offsets_->build();
        }

        // Construct double Elias-Fano index for bucket cumulative keys and bit positions
        std::vector<uint64_t> cumulative_keys{bucket_size_accumulator_.begin(), bucket_size_accumulator_.end()};
        std::vector<uint64_t> positions(bucket_position_accumulator_.begin(), bucket_position_accumulator_.end());
        double_ef_index_.build(cumulative_keys, positions);

        built_ = true;

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
        const uint8_t start_seed_length = sizeof(kStartSeed) / sizeof(uint64_t);
        index_output_stream.write(reinterpret_cast<const char*>(&start_seed_length), sizeof(uint8_t));
        SILK_DEBUG << "[index] written start seed length: " << int(start_seed_length);

        for (const uint64_t s : kStartSeed) {
            endian::store_big_u64(uint64_buffer.data(), s);
            index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
        }
        SILK_DEBUG << "[index] written start seed: " << kStartSeed;

        // Write out index flag
        const uint8_t enum_index_flag = double_enum_index_ ? 1 : 0;
        index_output_stream.write(reinterpret_cast<const char*>(&enum_index_flag), sizeof(uint8_t));

        // Write out Elias-Fano code for offsets (if any)
        if (double_enum_index_) {
            index_output_stream << *ef_offsets_;
            SILK_DEBUG << "[index] written EF code for offsets [size: " << ef_offsets_->count() - 1 << "]";
        }

        // Write out the number of Golomb-Rice code params
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
        bucket_collector_.clear();
        offset_collector_.clear();
        current_bucket_.clear();
        current_bucket_offsets_.clear();
        max_offset_ = 0;
        bucket_size_accumulator_.resize(1);
        bucket_position_accumulator_.resize(1);
        salt_++;
        hasher_->reset_seed(salt_);
    }

    /** Returns the value associated with the given 128-bit hash.
     *
     * Note that this method is mainly useful for benchmarking.
     * @param hash a 128-bit hash.
     * @return the associated value.
     */
    size_t operator()(const hash128_t& hash) {
        if (!built_) throw std::logic_error{"perfect hash function not built yet"};

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

    //! Return the value associated with the given key
    size_t operator()(const std::string& key) const { return operator()(murmur_hash_3(key.c_str(), key.size())); }

    //! Return the number of keys used to build the RecSplit instance
    inline size_t size() const { return key_count_; }

  private:
    static inline std::size_t skip_bits(std::size_t m) { return memo[m] & 0xFFFF; }

    static inline std::size_t skip_nodes(std::size_t m) { return (memo[m] >> 16) & 0x7FF; }

    static constexpr uint64_t golomb_param(const std::size_t m, const std::array<uint32_t, kMaxBucketSize>& memo) {
        if (m > golomb_param_max_index_) golomb_param_max_index_ = m;
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
    bool recsplit_current_bucket(std::ofstream& index_output_stream) {
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
                    SILK_ERROR << "collision detected key=" << current_bucket_[i - 1];
                    return true;
                }
            }
            buffer_bucket_.reserve(current_bucket_.size());
            buffer_offsets_.reserve(current_bucket_offsets_.size());
            buffer_bucket_.resize(current_bucket_.size());
            buffer_offsets_.resize(current_bucket_.size());

            std::vector<uint32_t> unary;
            recsplit(current_bucket_, current_bucket_offsets_, unary, index_output_stream);
            gr_builder_.append_unary_all(unary);
        } else {
            for (const auto offset : current_bucket_offsets_) {
                Bytes uint64_buffer(8, '\0');
                endian::store_big_u64(uint64_buffer.data(), offset);
                index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), 8);
                SILK_DEBUG << "[index] written offset: " << offset;
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
        return false;
    }

    //! Apply the RecSplit algorithm to the given bucket
    void recsplit(std::vector<uint64_t>& bucket,
                  std::vector<uint64_t>& offsets,
                  std::vector<uint32_t>& unary,
                  std::ofstream& index_ofs) {
        recsplit(/*.level=*/0, bucket, offsets, /*.start=*/0, /*.end=*/bucket.size(), unary, index_ofs);
    }

    void recsplit(int level,
                  std::vector<uint64_t>& bucket,
                  std::vector<uint64_t>& offsets,
                  std::size_t start,
                  std::size_t end,
                  std::vector<uint32_t>& unary,
                  std::ofstream& index_ofs) {
        uint64_t salt = kStartSeed[level];
        const uint16_t m = end - start;
        SILKWORM_ASSERT(m > 1);
        if (m <= LEAF_SIZE) {
            // No need to build aggregation levels - just find bijection
            if (level == 7) {
                SILK_DEBUG << "[index] recsplit m: " << m << " salt: " << salt << " start: " << start << " bucket[start]=" << bucket[start]
                           << " current_bucket_id_=" << current_bucket_id_;
                for (std::size_t j = 0; j < m; j++) {
                    SILK_DEBUG << "[index] buffer m: " << m << " start: " << start << " j: " << j << " bucket[start + j]=" << bucket[start + j];
                }
            }
            while (true) {
                uint32_t mask{0};
                bool fail{false};
                for (uint16_t i{0}; !fail && i < m; i++) {
                    uint32_t bit = uint32_t(1) << remap16(remix(bucket[start + i] + salt), m);
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
                std::size_t j = remap16(remix(bucket[start + i] + salt), m);
                buffer_offsets_[j] = offsets[start + i];
            }
            Bytes uint64_buffer(8, '\0');
            for (auto i{0}; i < m; i++) {
                endian::store_big_u64(uint64_buffer.data(), buffer_offsets_[i]);
                index_ofs.write(reinterpret_cast<const char*>(uint64_buffer.data() + (8 - bytes_per_record_)), bytes_per_record_);
                if (level == 0) {
                    SILK_DEBUG << "[index] written offset: " << buffer_offsets_[i];
                }
            }
            salt -= kStartSeed[level];
            const auto log2golomb = golomb_param(m, memo);
            gr_builder_.append_fixed(salt, log2golomb);
            unary.push_back(static_cast<uint32_t>(salt >> log2golomb));
        } else {
            const auto [fanout, unit] = SplitStrategy::split_params(m);

            SILK_DEBUG << "[index] m > _leaf: m=" << m << " fanout=" << fanout << " unit=" << unit;

            SILKWORM_ASSERT(fanout <= kLowerAggregationBound);
            count_.resize(fanout);
            while (true) {
                std::fill(count_.begin(), count_.end(), 0);
                for (std::size_t i{0}; i < m; i++) {
                    count_[uint16_t(remap16(remix(bucket[start + i] + salt), m)) / unit]++;
                }
                bool broken{false};
                for (std::size_t i = 0; i < fanout - 1; i++) {
                    broken = broken || (count_[i] != unit);
                }
                if (!broken) break;
                salt++;
            }
            for (std::size_t i{0}, c{0}; i < fanout; i++, c += unit) {
                count_[i] = c;
            }
            for (std::size_t i{0}; i < m; i++) {
                auto j = uint16_t(remap16(remix(bucket[start + i] + salt), m)) / unit;
                buffer_bucket_[count_[j]] = bucket[start + i];
                buffer_offsets_[count_[j]] = offsets[start + i];
                count_[j]++;
            }
            std::copy(buffer_bucket_.data(), buffer_bucket_.data() + m, bucket.data() + start);
            std::copy(buffer_offsets_.data(), buffer_offsets_.data() + m, offsets.data() + start);

            salt -= kStartSeed[level];
            const auto log2golomb = golomb_param(m, memo);
            gr_builder_.append_fixed(salt, log2golomb);
            unary.push_back(static_cast<uint32_t>(salt >> log2golomb));

            std::size_t i;
            for (i = 0; i < m - unit; i += unit) {
                recsplit(level + 1, bucket, offsets, start + i, start + i + unit, unary, index_ofs);
            }
            if (m - i > 1) {
                recsplit(level + 1, bucket, offsets, start + i, end, unary, index_ofs);
            } else if (m - i == 1) {
                Bytes uint64_buffer(8, '\0');
                endian::store_big_u64(uint64_buffer.data(), offsets[start + i]);
                index_ofs.write(reinterpret_cast<const char*>(uint64_buffer.data() + (8 - bytes_per_record_)), bytes_per_record_);
                if (level == 0) {
                    SILK_DEBUG << "[index] written offset: " << offsets[start + i];
                }
            }
        }
    }

    hash128_t inline murmur_hash_3(const void* data, const size_t length) {
        hash128_t h{};
        hasher_->hash_x64_128(data, length, &h);
        return h;
    }

    // Maps a 128-bit to a bucket using the first 64-bit half.
    inline uint64_t hash128_to_bucket(const hash128_t& hash) const { return remap128(hash.first, bucket_count_); }

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
    static inline uint16_t golomb_param_max_index_{0};

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
    uint64_t keys_added_{0};

    //! Minimum delta for Elias-Fano encoding of "enum -> offset" index
    uint64_t min_delta_{0};

    //! Last previously added offset (for calculating minimum delta for Elias-Fano encoding of "enum -> offset" index)
    uint64_t previous_offset_{0};

    //! Maximum value of offset used to decide how many bytes to use for Elias-Fano encoding
    uint64_t max_offset_{0};

    //! Number of bytes used per index record
    uint8_t bytes_per_record_{0};

    //! Identifier of the current bucket being accumulated
    uint64_t current_bucket_id_{0};

    //! 64-bit fingerprints of keys in the current bucket accumulated before the recsplit is performed for that bucket
    std::vector<uint64_t> current_bucket_;

    //! Index offsets for the current bucket
    std::vector<uint64_t> current_bucket_offsets_;

    //! Flag indicating if two-level index "recsplit -> enum" + "enum -> offset" is required
    bool double_enum_index_{true};

    //! Flag indicating that the MPHF has been built and no more keys can be added
    bool built_{false};

    //! The ETL collector sorting keys by offset
    etl::Collector offset_collector_{};

    //! The ETL collector sorting keys by bucket
    etl::Collector bucket_collector_{};

    //! Accumulator for size of every bucket
    std::vector<int64_t> bucket_size_accumulator_;

    //! Accumulator for position of every bucket in the encoding of the hash function
    std::vector<int64_t> bucket_position_accumulator_;

    //! Temporary buffer for current bucket
    std::vector<uint64_t> buffer_bucket_;

    //! Temporary buffer for current offsets
    std::vector<uint64_t> buffer_offsets_;

    //! Seed for Murmur3 hash used for converting keys to 64-bit values and assigning to buckets
    uint32_t salt_{0};

    //! Murmur3 hash factory
    std::unique_ptr<Murmur3> hasher_;

    //! Temporary counters of key remapped occurrences
    std::vector<std::size_t> count_;
};

constexpr std::size_t kLeafSize{8};
using RecSplit8 = RecSplit<kLeafSize>;

template <>
const std::array<uint32_t, kMaxBucketSize> RecSplit8::memo;

}  // namespace silkworm::succinct

#pragma GCC diagnostic pop
