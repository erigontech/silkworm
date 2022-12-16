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
#include <random>
#include <string>
#include <vector>

#include <gsl/util>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/etl/collector.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wunused-variable"
#if defined(__clang__)
#pragma GCC diagnostic ignored "-Winvalid-constexpr"
#endif /* defined(__clang__) */
#pragma GCC diagnostic ignored "-Wsign-compare"

#include <silkworm/recsplit/function/elias_fano.hpp>
#include <silkworm/recsplit/function/golomb_rice.hpp>
#include <silkworm/recsplit/support/murmur_hash3.hpp>
#include <silkworm/recsplit/util/Vector.hpp>

namespace sux::function {

using namespace std;
using namespace std::chrono;

// Assumed *maximum* size of a bucket. Works with high probability up to average bucket size ~2000.
static const int MAX_BUCKET_SIZE = 3000;

static const int MAX_LEAF_SIZE = 24;
static const int MAX_FANOUT = 32;

#if defined(MORESTATS) && !defined(STATS)
#define STATS
#endif

#ifdef MORESTATS

#define MAX_LEVEL_TIME (20)

static constexpr double log2e = 1.44269504089;
static uint64_t num_bij_trials[MAX_LEAF_SIZE], num_split_trials;
static uint64_t num_bij_evals[MAX_LEAF_SIZE], num_split_evals;
static uint64_t bij_count[MAX_LEAF_SIZE], split_count;
static uint64_t expected_split_trials, expected_split_evals;
static uint64_t bij_unary, bij_fixed, bij_unary_golomb, bij_fixed_golomb;
static uint64_t split_unary, split_fixed, split_unary_golomb, split_fixed_golomb;
static uint64_t max_split_code, min_split_code, sum_split_codes;
static uint64_t max_bij_code, min_bij_code, sum_bij_codes;
static uint64_t sum_depths;
static uint64_t time_bij;
static uint64_t time_split[MAX_LEVEL_TIME];
#endif

// Starting seed at given distance from the root (extracted at random).
static const uint64_t start_seed[] = {0x106393c187cae21a, 0x6453cec3f7376937, 0x643e521ddbd2be98, 0x3740c6412f6572cb, 0x717d47562f1ce470, 0x4cd6eb4c63befb7c, 0x9bfd8c5e18c8da73,
                                      0x082f20e10092a9a3, 0x2ada2ce68d21defc, 0xe33cb4f3e7c6466b, 0x3980be458c509c59, 0xc466fd9584828e8c, 0x45f0aabe1a61ede6, 0xf6e7b8b33ad9b98d,
                                      0x4ef95e25f4b4983d, 0x81175195173b92d3, 0x4e50927d8dd15978, 0x1ea2099d1fafae7f, 0x425c8a06fbaaa815, 0xcd4216006c74052a};

/** David Stafford's (http://zimbry.blogspot.com/2011/09/better-bit-mixing-improving-on.html)
 * 13th variant of the 64-bit finalizer function in Austin Appleby's
 * MurmurHash3 (https://github.com/aappleby/smhasher).
 *
 * @param z a 64-bit integer.
 * @return a 64-bit integer obtained by mixing the bits of `z`.
 */

uint64_t inline remix(uint64_t z) {
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

/** 128-bit hashes.
 *
 * In the construction of RecSplit, keys are replaced with instances
 * of this class using SpookyHash, first thing.
 * Moreover, it is possible to build and query RecSplit instances using 128-bit
 * random hashes only (mainly for benchmarking purposes).
 */

struct hash128_t {
    uint64_t first, second;  // TODO(canepat) rename first->hi, second->lo
    bool operator<(const hash128_t& o) const { return first < o.first || second < o.second; }
};

// Quick replacements for min/max on not-so-large integers.

static constexpr inline uint64_t min(int64_t x, int64_t y) { return static_cast<uint64_t>(y + ((x - y) & ((x - y) >> 63))); }
static constexpr inline uint64_t max(int64_t x, int64_t y) { return static_cast<uint64_t>(x - ((x - y) & ((x - y) >> 63))); }

// Optimal Golomb-Rice parameters for leaves.
static constexpr uint8_t bij_memo[] = {0, 0, 0, 1, 3, 4, 5, 7, 8, 10, 11, 12, 14, 15, 16, 18, 19, 21, 22, 23, 25, 26, 28, 29, 30};

#ifdef MORESTATS
// Optimal Golomb code moduli for leaves (for stats).
static constexpr uint64_t bij_memo_golomb[] = {0, 0, 1, 3, 7, 18, 45, 113, 288, 740,
                                               1910, 4954, 12902, 33714, 88350, 232110, 611118, 1612087, 4259803, 11273253,
                                               29874507, 79265963, 210551258, 559849470, 1490011429, 3968988882, 10580669970, 28226919646, 75354118356};
#endif

/** A class emboding the splitting strategy of RecSplit.
 *
 *  Note that this class is used _for statistics only_. The splitting strategy is embedded
 *  into the generation code, which uses only the public fields SplittingStrategy::lower_aggr and SplittingStrategy::upper_aggr.
 */

template <size_t LEAF_SIZE>
class SplittingStrategy {
    static constexpr size_t _leaf = LEAF_SIZE;
    static_assert(_leaf >= 1);
    static_assert(_leaf <= MAX_LEAF_SIZE);
    size_t m, curr_unit, curr_index, last_unit;
    size_t _fanout;
    size_t unit;

    inline size_t part_size() const { return (curr_index < _fanout - 1) ? unit : last_unit; }

  public:
    /** The lower bound for primary (lower) key aggregation. */
    static inline const size_t lower_aggr = _leaf * max(2, ceil(0.35 * _leaf + 1. / 2));
    /** The lower bound for secondary (upper) key aggregation. */
    static inline const size_t upper_aggr = lower_aggr * (_leaf < 7 ? 2 : ceil(0.21 * _leaf + 9. / 10));

    static inline void split_params(const size_t m, size_t& fanout, size_t& unit) {
        if (m > upper_aggr) {  // High-level aggregation (fanout 2)
            unit = upper_aggr * (uint16_t(m / 2 + upper_aggr - 1) / upper_aggr);
            fanout = 2;
        } else if (m > lower_aggr) {  // Second-level aggregation
            unit = lower_aggr;
            fanout = uint16_t(m + lower_aggr - 1) / lower_aggr;
        } else {  // First-level aggregation//
            unit = _leaf;
            fanout = uint16_t(m + _leaf - 1) / _leaf;
        }
    }

    // Note that you can call this iterator only *once*.
    class split_iterator {
        SplittingStrategy* strat;

      public:
        using value_type = size_t;
        using difference_type = ptrdiff_t;
        using pointer = size_t*;
        using reference = size_t&;
        using iterator_category = input_iterator_tag;

        split_iterator(SplittingStrategy* strategy) : strat(strategy) {}
        size_t operator*() const { return strat->curr_unit; }
        size_t* operator->() const { return &strat->curr_unit; }
        split_iterator& operator++() {
            ++strat->curr_index;
            strat->curr_unit = strat->part_size();
            strat->last_unit -= strat->curr_unit;
            return *this;
        }
        bool operator==(const split_iterator& other) const { return strat == other.strat; }
        bool operator!=(const split_iterator& other) const { return !(*this == other); }
    };

    explicit SplittingStrategy(size_t mm) : m(mm), last_unit(mm), curr_index(0), curr_unit(0) {
        split_params(m, _fanout, unit);
        this->curr_unit = part_size();
        this->last_unit -= this->curr_unit;
    }

    split_iterator begin() { return split_iterator(this); }
    split_iterator end() { return split_iterator(nullptr); }

    inline size_t fanout() { return this->_fanout; }
};

#define skip_bits(m) (memo[m] & 0xFFFF)
#define skip_nodes(m) ((memo[m] >> 16) & 0x7FF)

/**
 *
 * A class for storing minimal perfect hash functions. The template
 * parameter decides how large a leaf will be. Larger leaves imply
 * slower construction, but less space and faster evaluation.
 *
 * @tparam LEAF_SIZE the size of a leaf; typicals value range from 6 to 8
 * for fast, small maps, or up to 16 for very compact functions.
 * @tparam AT a type of memory allocation out of sux::util::AllocType.
 */

template <size_t LEAF_SIZE, util::AllocType AT = util::AllocType::MALLOC>
class RecSplit {
    using SplitStrategy = SplittingStrategy<LEAF_SIZE>;
    using GolombRiceVector = RiceBitVector<AT>;
    using GolombRiceBuilder = typename GolombRiceVector::Builder;
    using EliasFano = EliasFanoList32<AT>;
    using DoubleEliasFano = DoubleEliasFanoList16<AT>;

    static constexpr size_t _leaf = LEAF_SIZE;
    static const size_t lower_aggr;
    static const size_t upper_aggr;

    static constexpr int golomb_param(const int m, const array<uint32_t, MAX_BUCKET_SIZE>& memo) {
        return memo[m] >> 27;
    }

    // Generates the precomputed table of 32-bit values holding the Golomb-Rice code
    // of a splitting (upper 5 bits), the number of nodes in the associated subtree
    // (following 11 bits) and the sum of the Golomb-Rice codelengths in the same
    // subtree (lower 16 bits).
    static constexpr void _fill_golomb_rice(const int m, array<uint32_t, MAX_BUCKET_SIZE>* memo) {
        array<int, MAX_FANOUT> k{0};

        size_t fanout = 0, unit = 0;
        SplittingStrategy<LEAF_SIZE>::split_params(m, fanout, unit);

        k[fanout - 1] = m;
        for (size_t i = 0; i < fanout - 1; ++i) {
            k[i] = unit;
            k[fanout - 1] -= k[i];
        }

        double sqrt_prod = 1;
        for (size_t i = 0; i < fanout; ++i) sqrt_prod *= sqrt(k[i]);

        const double p = sqrt(m) / (pow(2 * M_PI, (fanout - 1.) / 2) * sqrt_prod);
        auto golomb_rice_length = static_cast<uint32_t>(ceil(log2(-log((sqrt(5) + 1) / 2) / log1p(-p))));  // log2 Golomb modulus

        assert(golomb_rice_length <= 0x1F);  // Golomb-Rice code, stored in the 5 upper bits
        (*memo)[m] = golomb_rice_length << 27;
        for (size_t i = 0; i < fanout; ++i) golomb_rice_length += (*memo)[k[i]] & 0xFFFF;
        assert(golomb_rice_length <= 0xFFFF);  // Sum of Golomb-Rice codeslengths in the subtree, stored in the lower 16 bits
        (*memo)[m] |= golomb_rice_length;

        uint32_t nodes = 1;
        for (size_t i = 0; i < fanout; ++i) nodes += ((*memo)[k[i]] >> 16) & 0x7FF;
        assert(LEAF_SIZE < 3 || nodes <= 0x7FF);  // Number of nodes in the subtree, stored in the middle 11 bits
        (*memo)[m] |= nodes << 16;
    }

    static constexpr array<uint32_t, MAX_BUCKET_SIZE> fill_golomb_rice() {
        array<uint32_t, MAX_BUCKET_SIZE> memo{0};
        size_t s = 0;
        for (; s <= LEAF_SIZE; ++s) memo[s] = bij_memo[s] << 27 | (s > 1) << 16 | bij_memo[s];
        for (; s < MAX_BUCKET_SIZE; ++s) _fill_golomb_rice(s, &memo);
        return memo;
    }

    // For each bucket size, the Golomb-Rice parameter (upper 8 bits) and the number of bits to
    // skip in the fixed part of the tree (lower 24 bits).
    static const array<uint32_t, MAX_BUCKET_SIZE> memo;

    size_t bucket_size;            // TODO(canepat) rename bucket_size_
    size_t keys_count;             // TODO(canepat) rename key_count_
    size_t nbuckets;               // TODO(canepat) rename bucket_count_
    GolombRiceVector descriptors;  // TODO(canepat) golomb_rice_codes_

    //! Helper to build Golomb-Rice (GR) codes of splitting and bijection indices
    GolombRiceBuilder gr_builder_;

    DoubleEliasFano ef;

    //! Helper to encode the sequences of cumulative number of keys and cumulative bit offsets of buckets in the GR code
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
    silkworm::etl::Collector offset_collector_{};

    //! The ETL collector sorting keys by bucket
    silkworm::etl::Collector bucket_collector_{};

    //! Accumulator for size of every bucket
    std::vector<int64_t> bucket_size_accumulator_;

    //! Accumulator for position of every bucket in the encoding of the hash function
    std::vector<int64_t> bucket_position_accumulator_;

    //!
    std::vector<uint64_t> buffer_;  // TODO(canepat) rename buffer_bucket_

    //!
    std::vector<uint64_t> buffer_offsets_;

    //! Seed for Murmur3 hash used for converting keys to 64-bit values and assigning to buckets
    uint32_t salt_{0};

    //! Murmur3 hash factory
    std::unique_ptr<Murmur3> hasher_;

  public:
    RecSplit(const size_t _keys_count, const size_t _bucket_size, std::filesystem::path index_path, uint64_t base_data_id, uint32_t salt = 0)
        : bucket_size(_bucket_size),
          keys_count(_keys_count),
          nbuckets((keys_count + bucket_size - 1) / bucket_size),
          base_data_id_(base_data_id),
          index_path_(std::move(index_path)) {
        bucket_size_accumulator_.reserve(nbuckets + 1);
        bucket_position_accumulator_.reserve(nbuckets + 1);
        current_bucket_.reserve(bucket_size);
        current_bucket_offsets_.reserve(bucket_size);

        // Generate random salt for murmur3 hash
        std::random_device rand_dev;
        std::mt19937 rand_gen32{rand_dev()};
        salt_ = salt != 0 ? salt : rand_gen32();
        salt_ = 1;  // TODO(canepat) remove
        hasher_ = std::make_unique<Murmur3>(salt_);
    }

    void add_key(const void* key_data, const size_t key_length, uint64_t offset) {
        if (built_) {
            throw std::logic_error{"cannot add key after perfect hash function has been built"};
        }

        const auto key_hash = murmur_hash_3(key_data, key_length);
        if (keys_added_ % 100'000 == 0) {
            SILK_DEBUG << "[index] add key hash: first=" << key_hash.first << " second=" << key_hash.second << " offset=" << offset;
        }

        silkworm::Bytes bucket_key(16, '\0');
        silkworm::endian::store_big_u64(bucket_key.data(), hash128_to_bucket(key_hash));
        silkworm::endian::store_big_u64(bucket_key.data() + sizeof(uint64_t), key_hash.second);
        silkworm::Bytes offset_key(8, '\0');
        silkworm::endian::store_big_u64(offset_key.data(), offset);

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

            silkworm::Bytes current_key_count(8, '\0');
            silkworm::endian::store_big_u64(current_key_count.data(), keys_added_);
            bucket_collector_.collect({bucket_key, current_key_count});
        } else {
            bucket_collector_.collect({bucket_key, offset_key});
        }
        keys_added_++;
        previous_offset_ = offset;
    }

    void add_key(const string& key, uint64_t offset) {
        add_key(key.c_str(), key.size(), offset);
    }

    //! Build the MPHF using the RecSplit algorithm and save the resulting index file
    //! \warning duplicate keys will cause this method to never return
    [[nodiscard]] bool build() {
        if (built_) {
            throw std::logic_error{"perfect hash function already built"};
        }
        if (keys_added_ != keys_count) {
            throw std::logic_error{"keys expected: " + std::to_string(keys_count) + " added: " + std::to_string(keys_added_)};
        }
        const auto tmp_index_path{std::filesystem::path{index_path_}.concat(".tmp")};
        std::ofstream index_output_stream{tmp_index_path, std::ios::binary};
        auto index_output_stream_flush = gsl::finally([&]() { index_output_stream.flush(); });  // TODO(canepat) check if necessary
        SILK_DEBUG << "[index] creating temporary index file: " << tmp_index_path.string();

        // Write minimal app-specific data ID in the index file
        silkworm::Bytes uint64_buffer(8, '\0');
        silkworm::endian::store_big_u64(uint64_buffer.data(), base_data_id_);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
        SILK_DEBUG << "[index] written base data ID: " << base_data_id_;

        // Write number of keys
        silkworm::endian::store_big_u64(uint64_buffer.data(), keys_added_);
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
            mdbx::cursor empty_cursor{};
            bucket_collector_.load(empty_cursor, [&](const silkworm::etl::Entry& entry, mdbx::cursor&, MDBX_put_flags_t) {
                // k is the big-endian encoding of the bucket number and the v is the key that is assigned into that bucket
                const uint64_t bucket_id = silkworm::endian::load_big_u64(entry.key.data());
                SILK_TRACE << "[index] processing bucket_id=" << bucket_id;
                if (current_bucket_id_ != bucket_id) {
                    if (current_bucket_id_ != std::numeric_limits<uint64_t>::max()) {
                        bool collision = recsplit_current_bucket(index_output_stream);
                        if (collision) throw CollisionError{bucket_id};
                    }
                    current_bucket_id_ = bucket_id;
                }
                current_bucket_.emplace_back(silkworm::endian::load_big_u64(entry.key.data() + sizeof(uint64_t)));
                current_bucket_offsets_.emplace_back(silkworm::endian::load_big_u64(entry.value.data()));
            });
        } catch (const CollisionError& error) {
            SILK_WARN << "[index] collision detected for bucket=" << error.bucket_id;
            return true;
        }
        if (!current_bucket_.empty()) {
            bool collision_detected = recsplit_current_bucket(index_output_stream);
            if (collision_detected) return true;
        }
        gr_builder_.appendFixed(1, 1);  // Sentinel (avoids checking for parts of size 1)
        descriptors = gr_builder_.build();

#ifndef NDEBUG
        index_output_stream.flush();
        std::ifstream index_input_stream{tmp_index_path, std::ios::binary};
        const auto index_file_size = static_cast<long>(std::filesystem::file_size(tmp_index_path));
        SILK_DEBUG << "[index] index_file_size=" << index_file_size;
        std::vector<char> read_buffer;
        read_buffer.resize(index_file_size);
        index_input_stream.read(read_buffer.data(), index_file_size);
        index_input_stream.close();
        if (index_file_size != 17 + keys_added_ * bytes_per_record_) {
            SILK_CRIT << "size expected=" << 17 + keys_added_ * bytes_per_record_ << " got=" << index_file_size;
            SILKWORM_ASSERT(false);
        }
#endif

        SILK_INFO << "[index] writing file=" << index_path_.string();
        if (double_enum_index_) {
            ef_offsets_ = std::make_unique<EliasFano>(keys_added_, max_offset_);
            mdbx::cursor empty_cursor{};
            offset_collector_.load(empty_cursor, [&](const silkworm::etl::Entry& entry, mdbx::cursor&, MDBX_put_flags_t) {
                const uint64_t offset = silkworm::endian::load_big_u64(entry.key.data());
                ef_offsets_->add_offset(offset);
            });
            ef_offsets_->build();
        }

        // Construct double Elias-Fano index for bucket cumulative keys and bit positions
        vector<uint64_t> cumulative_keys{bucket_size_accumulator_.begin(), bucket_size_accumulator_.end()};
        vector<uint64_t> positions(bucket_position_accumulator_.begin(), bucket_position_accumulator_.end());
        ef.build(cumulative_keys, positions);

        built_ = true;

        // Write out bucket count, bucket size, leaf size
        silkworm::endian::store_big_u64(uint64_buffer.data(), nbuckets);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
        SILK_DEBUG << "[index] written bucket count: " << nbuckets;

        silkworm::endian::store_big_u16(uint64_buffer.data(), bucket_size);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint16_t));
        SILK_DEBUG << "[index] written bucket size: " << bucket_size;

        silkworm::endian::store_big_u16(uint64_buffer.data(), _leaf);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint16_t));
        SILK_DEBUG << "[index] written leaf size: " << _leaf;

        // Write out salt
        silkworm::endian::store_big_u32(uint64_buffer.data(), salt_);
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint32_t));
        SILK_DEBUG << "[index] written murmur3 salt: " << salt_;

        // Write out start seeds
        const uint8_t start_seed_length = sizeof(start_seed) / sizeof(uint64_t);
        index_output_stream.write(reinterpret_cast<const char*>(&start_seed_length), sizeof(uint8_t));
        SILK_DEBUG << "[index] written start seed length: " << int(start_seed_length);

        for (const uint64_t s : start_seed) {
            silkworm::endian::store_big_u64(uint64_buffer.data(), s);
            index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
        }
        SILK_DEBUG << "[index] written start seed: " << start_seed;

        // Write out index flag
        const uint8_t enum_index_flag = double_enum_index_ ? 1 : 0;
        index_output_stream.write(reinterpret_cast<const char*>(&enum_index_flag), sizeof(uint8_t));

        // Write out Elias-Fano code for offsets (if any)
        if (double_enum_index_) {
            index_output_stream << ef_offsets_;
            SILK_DEBUG << "[index] written EF code for offsets [size: " << ef_offsets_->count() << "]";
        }

        // Write out the size of Golomb-Rice code params
        silkworm::endian::store_big_u32(uint64_buffer.data(), descriptors.getBits());
        index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint32_t));
        SILK_DEBUG << "[index] written GR code size: " << descriptors.getBits();

        // Write out Golomb-Rice code
        index_output_stream << descriptors;

        // Write out Elias-Fano code for bucket cumulative keys and bit positions
        // TODO(canepat) check data vector size
        index_output_stream << ef;

        index_output_stream.flush();
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
        const size_t bucket = hash128_to_bucket(hash);
        uint64_t cum_keys, cum_keys_next, bit_pos;
        ef.get(bucket, cum_keys, cum_keys_next, bit_pos);

        // Number of keys in this bucket
        size_t m = cum_keys_next - cum_keys;
        auto reader = descriptors.reader();
        reader.readReset(bit_pos, skip_bits(m));
        int level = 0;

        while (m > upper_aggr) {  // fanout = 2
            const auto d = reader.readNext(golomb_param(m, memo));
            const size_t hmod = remap16(remix(hash.second + d + start_seed[level]), m);

            const uint32_t split = ((uint16_t(m / 2 + upper_aggr - 1) / upper_aggr)) * upper_aggr;
            if (hmod < split) {
                m = split;
            } else {
                reader.skipSubtree(skip_nodes(split), skip_bits(split));
                m -= split;
                cum_keys += split;
            }
            level++;
        }
        if (m > lower_aggr) {
            const auto d = reader.readNext(golomb_param(m, memo));
            const size_t hmod = remap16(remix(hash.second + d + start_seed[level]), m);

            const int part = uint16_t(hmod) / lower_aggr;
            m = min(lower_aggr, m - part * lower_aggr);
            cum_keys += lower_aggr * part;
            if (part) reader.skipSubtree(skip_nodes(lower_aggr) * part, skip_bits(lower_aggr) * part);
            level++;
        }

        if (m > _leaf) {
            const auto d = reader.readNext(golomb_param(m, memo));
            const size_t hmod = remap16(remix(hash.second + d + start_seed[level]), m);

            const int part = uint16_t(hmod) / _leaf;
            m = min(_leaf, m - part * _leaf);
            cum_keys += _leaf * part;
            if (part) reader.skipSubtree(part, skip_bits(_leaf) * part);
            level++;
        }

        const auto b = reader.readNext(golomb_param(m, memo));
        return cum_keys + remap16(remix(hash.second + b + start_seed[level]), m);
    }

    //! Return the value associated with the given key
    size_t operator()(const string& key) const { return operator()(murmur_hash_3(key.c_str(), key.size())); }

    //! Return the number of keys used to build the RecSplit instance
    inline size_t size() const { return this->keys_count; }

  private:
    //! Compute and store the splittings and bijections of the current bucket
    bool recsplit_current_bucket(std::ofstream& index_output_stream) {
        // Extend bucket size accumulator to accommodate current bucket index + 1
        while (bucket_size_accumulator_.size() <= (current_bucket_id_ + 1)) {
            bucket_size_accumulator_.push_back(bucket_size_accumulator_.back());
        }
        bucket_size_accumulator_[current_bucket_id_ + 1] += current_bucket_.size();
        SILKWORM_ASSERT(bucket_size_accumulator_[current_bucket_id_ + 1] >= bucket_size_accumulator_[current_bucket_id_]);
        // TODO(canepat) check bucket_size_accumulator_.back() += current_bucket_.size();

        // Sets of size 0 and 1 are not further processed, just write them to index
        if (current_bucket_.size() > 1) {
            for (std::size_t i{1}; i < current_bucket_.size(); ++i) {
                if (current_bucket_[i] == current_bucket_[i - 1]) {
                    SILK_ERROR << "collision detected key=" << current_bucket_[i - 1];
                    return true;
                }
            }
            buffer_.reserve(current_bucket_.size());
            buffer_offsets_.reserve(current_bucket_offsets_.size());
            buffer_.resize(current_bucket_.size());
            buffer_offsets_.resize(current_bucket_.size());

            vector<uint32_t> unary;
            recsplit(current_bucket_, current_bucket_offsets_, unary, index_output_stream);
            gr_builder_.appendUnaryAll(unary);
        } else {
            for (const auto offset : current_bucket_offsets_) {
                silkworm::Bytes uint64_buffer(8, '\0');
                silkworm::endian::store_big_u64(uint64_buffer.data(), offset);
                index_output_stream.write(reinterpret_cast<const char*>(uint64_buffer.data()), 8);
                SILK_DEBUG << "[index] written offset: " << offset;
            }
        }
        // Extend bucket position accumulator to accommodate current bucket index + 1
        while (bucket_position_accumulator_.size() <= current_bucket_id_ + 1) {
            bucket_position_accumulator_.push_back(bucket_position_accumulator_.back());
        }
        bucket_position_accumulator_[current_bucket_id_ + 1] = gr_builder_.getBits();
        SILKWORM_ASSERT(bucket_position_accumulator_[current_bucket_id_ + 1] >= bucket_position_accumulator_[current_bucket_id_]);
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
        uint64_t salt = start_seed[level];
        const uint16_t m = end - start;
        SILKWORM_ASSERT(m > 1);
        if (m <= _leaf) {
            // No need to build aggregation levels - just find bijection
            if (level == 7) {
                SILK_DEBUG << "[index] recsplit m: " << m << " salt: " << salt << " start: " << start << " bucket[start]=" << bucket[start]
                           << " current_bucket_id_=" << current_bucket_id_;
                for (std::size_t j = 0; j < m; j++) {
                    SILK_DEBUG << "[index] buffer m: " << m << " start: " << start << " j: " << j << " bucket[start + j]=" << bucket[start + j];
                }
            }
            uint32_t mask{0};
            while (true) {
                mask = 0;
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
            silkworm::Bytes uint64_buffer(8, '\0');
            for (auto i{0}; i < m; i++) {
                silkworm::endian::store_big_u64(uint64_buffer.data(), buffer_offsets_[i]);
                index_ofs.write(reinterpret_cast<const char*>(uint64_buffer.data() + (8 - bytes_per_record_)), bytes_per_record_);
                if (level == 0) {
                    SILK_DEBUG << "[index] written offset: " << buffer_offsets_[i];
                }
            }
            salt -= start_seed[level];
            const auto log2golomb = golomb_param(m, memo);
            gr_builder_.appendFixed(salt, log2golomb);
            unary.push_back(salt >> log2golomb);
        } else {
            std::size_t fanout{0}, unit{0};
            SplitStrategy::split_params(m, fanout, unit);

            SILK_DEBUG << "[index] m > _leaf: m=" << m << " fanout=" << fanout << " unit=" << unit;

            auto count = new std::size_t[fanout];  // Note that we never read count[fanout-1]
            // TODO(canepat) std::vector<std::size_t> count(fanout);
            while (true) {
                memset(count, 0, fanout * sizeof(std::size_t));
                for (std::size_t i{0}; i < m; i++) {
                    count[uint16_t(remap16(remix(bucket[start + i] + salt), m)) / unit]++;
                }
                bool broken{false};
                for (std::size_t i = 0; i < fanout - 1; i++) {
                    broken = broken || (count[i] != unit);
                }
                if (!broken) break;
                salt++;
            }
            for (std::size_t i = 0, c = 0; i < fanout; i++, c += unit) {
                count[i] = c;
            }
            for (std::size_t i{0}; i < m; i++) {
                auto j = uint16_t(remap16(remix(bucket[start + i] + salt), m)) / unit;
                buffer_[count[j]] = bucket[start + i];
                buffer_offsets_[count[j]] = offsets[start + i];
                count[j]++;
            }
            std::copy(buffer_.data(), buffer_.data() + m, bucket.data() + start);
            std::copy(buffer_offsets_.data(), buffer_offsets_.data() + m, offsets.data() + start);
            delete[] count;  // TODO(canepat) remove with std::vector<std::size_t> count(fanout);

            salt -= start_seed[level];
            const auto log2golomb = golomb_param(m, memo);
            gr_builder_.appendFixed(salt, log2golomb);
            unary.push_back(salt >> log2golomb);

            std::size_t i;
            for (i = 0; i < m - unit; i += unit) {
                recsplit(level + 1, bucket, offsets, start + i, start + i + unit, unary, index_ofs);
            }
            if (m - i > 1) {
                recsplit(level + 1, bucket, offsets, start + i, end, unary, index_ofs);
            } else if (m - i == 1) {
                silkworm::Bytes uint64_buffer(8, '\0');
                silkworm::endian::store_big_u64(uint64_buffer.data(), offsets[start + i]);
                index_ofs.write(reinterpret_cast<const char*>(uint64_buffer.data() + (8 - bytes_per_record_)), bytes_per_record_);
                if (level == 0) {
                    SILK_DEBUG << "[index] written offset: " << offsets[start + i];
                }
            }
        }
    }

    hash128_t inline murmur_hash_3(const void* data, const size_t length) {
        hash128_t h;
        hasher_->hash_x64_128(data, length, &h);
        return h;
    }

    // Maps a 128-bit to a bucket using the first 64-bit half.
    inline uint64_t hash128_to_bucket(const hash128_t& hash) const { return remap128(hash.first, nbuckets); }

    friend ostream& operator<<(ostream& os, const RecSplit<LEAF_SIZE, AT>& rs) {
        size_t leaf_size = LEAF_SIZE;
        os.write(reinterpret_cast<char*>(&leaf_size), sizeof(leaf_size));
        os.write(reinterpret_cast<char*>(&rs.bucket_size), sizeof(rs.bucket_size));
        os.write(reinterpret_cast<char*>(&rs.keys_count), sizeof(rs.keys_count));
        os << rs.descriptors;
        os << rs.ef;
        return os;
    }

    friend istream& operator>>(istream& is, RecSplit<LEAF_SIZE, AT>& rs) {
        size_t leaf_size;
        is.read(reinterpret_cast<char*>(&leaf_size), sizeof(leaf_size));
        if (leaf_size != LEAF_SIZE) {
            fprintf(stderr, "Serialized leaf size %d, code leaf size %d\n", int(leaf_size), int(LEAF_SIZE));
            abort();
        }
        is.read(reinterpret_cast<char*>(&rs.bucket_size), sizeof(bucket_size));
        is.read(reinterpret_cast<char*>(&rs.keys_count), sizeof(keys_count));
        rs.nbuckets = max(1, (rs.keys_count + rs.bucket_size - 1) / rs.bucket_size);

        is >> rs.descriptors;
        is >> rs.ef;
        return is;
    }
};

constexpr std::size_t kLeafSize{8};
using RecSplit8 = RecSplit<kLeafSize>;

template <>
const array<uint32_t, MAX_BUCKET_SIZE> RecSplit8::memo;

}  // namespace sux::function

#pragma GCC diagnostic pop
