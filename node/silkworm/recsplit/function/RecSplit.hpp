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
#include <cassert>
#include <chrono>
#include <cmath>
#include <fstream>
#include <string>
#include <vector>

#include <silkworm/common/endian.hpp>
#include <silkworm/etl/collector.hpp>

#include "../support/SpookyV2.hpp"
#include "../util/Vector.hpp"
#include "DoubleEF.hpp"
#include "RiceBitVector.hpp"

namespace sux::function {

using namespace std;
using namespace std::chrono;
using namespace silkworm;

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

typedef struct __hash128_t {
    uint64_t first, second;
    bool operator<(const __hash128_t& o) const { return first < o.first || second < o.second; }
    __hash128_t(const uint64_t f, const uint64_t s) {
        this->first = f;
        this->second = s;
    }
} hash128_t;

/** Convenience function hashing a key a returning a __hash128_t
 *
 * @param data a pointer to the key.
 * @param length the length in bytes of the key.
 * @param seed an additional seed.
 */

hash128_t inline spooky(const void* data, const size_t length, const uint64_t seed) {
    uint64_t h0 = seed, h1 = seed;
    SpookyHash::Hash128(data, length, &h0, &h1);
    return {h1, h0};
}

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
        } else {  // First-level aggregation
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

// Generates the precomputed table of 32-bit values holding the Golomb-Rice code
// of a splitting (upper 5 bits), the number of nodes in the associated subtree
// (following 11 bits) and the sum of the Golomb-Rice codelengths in the same
// subtree (lower 16 bits).

template <size_t LEAF_SIZE>
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

template <size_t LEAF_SIZE>
static constexpr array<uint32_t, MAX_BUCKET_SIZE> fill_golomb_rice() {
    array<uint32_t, MAX_BUCKET_SIZE> memo{0};
    size_t s = 0;
    for (; s <= LEAF_SIZE; ++s) memo[s] = bij_memo[s] << 27 | (s > 1) << 16 | bij_memo[s];
    for (; s < MAX_BUCKET_SIZE; ++s) _fill_golomb_rice<LEAF_SIZE>(s, &memo);
    return memo;
}

// Computes the Golomb modulu of a splitting (for statistics purposes only)

template <size_t LEAF_SIZE>
static constexpr uint64_t split_golomb_b(const int m) {
    array<int, MAX_FANOUT> k{0};

    size_t fanout = 0, part = 0, unit = 0;
    SplittingStrategy<LEAF_SIZE>::split_params(m, fanout, unit);

    k[fanout - 1] = m;
    for (size_t i = 0; i < fanout - 1; ++i) {
        k[i] = unit;
        k[fanout - 1] -= k[i];
    }

    double sqrt_prod = 1;
    for (size_t i = 0; i < fanout; ++i) sqrt_prod *= sqrt(k[i]);

    const double p = sqrt(m) / (pow(2 * M_PI, (fanout - 1.) / 2) * sqrt_prod);
    return ceil(-log(2 - p) / log1p(-p));  // Golomb modulus
}

// Computes the point at which one should stop to test whether
// bijection extraction failed (around the square root of the leaf size).

static constexpr array<uint8_t, MAX_LEAF_SIZE> fill_bij_midstop() {
    array<uint8_t, MAX_LEAF_SIZE> memo{0};
    for (std::size_t s = 0; s < MAX_LEAF_SIZE; ++s) memo[s] = s < static_cast<std::size_t>(ceil(2 * sqrt(s))) ? s : static_cast<std::size_t>(ceil(2 * sqrt(s)));
    return memo;
}

#define first_hash(k, len) spooky(k, len, 0)
#define golomb_param(m) (memo[m] >> 27)
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
    using SplitStrat = SplittingStrategy<LEAF_SIZE>;

    static constexpr size_t _leaf = LEAF_SIZE;
    static inline const size_t lower_aggr = SplitStrat::lower_aggr;
    static inline const size_t upper_aggr = SplitStrat::upper_aggr;

    // For each bucket size, the Golomb-Rice parameter (upper 8 bits) and the number of bits to
    // skip in the fixed part of the tree (lower 24 bits).
    static inline const array<uint32_t, MAX_BUCKET_SIZE> memo = fill_golomb_rice<LEAF_SIZE>();

    size_t bucket_size;
    size_t nbuckets;
    size_t keys_count;
    RiceBitVector<AT> descriptors;
    DoubleEF<AT> ef;

    //! The number of keys currently added
    uint64_t keys_added_{0};
    //! Minimum delta for Elias-Fano encoding of "enum -> offset" index
    uint64_t min_delta_{0};
    //! Last previously added offset (for calculating minimum delta for Elias-Fano encoding of "enum -> offset" index)
    uint64_t previous_offset_{0};
    //! Maximum value of offset used to decide how many bytes to use for Elias-Fano encoding
    uint64_t max_offset_{0};
    //! Flag indicating if two-level index "recsplit -> enum" + "enum -> offset" is required
    bool double_index_{true};
    //! Flag indicating that the MPHF has been built and no more keys can be added
    bool built_{false};
    //! The ETL collector sorting keys by offset
    etl::Collector offset_collector_{};
    //! The ETL collector sorting keys by bucket
    etl::Collector bucket_collector_{};

  public:
    RecSplit() {}

    RecSplit(const size_t _keys_count, const size_t _bucket_size) {
        this->bucket_size = _bucket_size;
        this->keys_count = _keys_count;
    }

    void add_key(const void* key_data, const size_t key_length, uint64_t offset) {
        if (built_) {
            throw std::logic_error{"cannot add key after perfect hash function has been built"};
        }

        const auto key_hash = first_hash(key_data, key_length);

        Bytes bucket_key(16, '\0');
        silkworm::endian::store_big_u64(bucket_key.data(), hash128_to_bucket(key_hash));
        silkworm::endian::store_big_u64(bucket_key.data() + sizeof(uint64_t), key_hash.second);
        Bytes offset_key(8, '\0');
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

        if (double_index_) {
            offset_collector_.collect({offset_key, {}});

            Bytes current_key_count(8, '\0');
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

    void build() {
        if (built_) {
            throw std::logic_error{"perfect hash function already built"};
        }
        if (keys_added_ != keys_count) {
            throw std::logic_error{"keys expected: " + std::to_string(keys_count) + " added: " + std::to_string(keys_added_)};
        }

        // TODO(canepat) handle keys from db
        // hash_gen(key_hashes_.data());

        built_ = true;
    }

    /** Builds a RecSplit instance using a given list of keys and bucket size.
     *
     * **Warning**: duplicate keys will cause this method to never return.
     *
     * @param keys a vector of strings.
     * @param bucket_size the desired bucket size; typical sizes go from
     * 100 to 2000, with smaller buckets giving slightly larger but faster
     * functions.
     */
    RecSplit(const vector<string>& keys, const size_t _bucket_size) {
        this->bucket_size = _bucket_size;
        this->keys_count = keys.size();
        hash128_t* h = static_cast<hash128_t*>(malloc(this->keys_count * sizeof(hash128_t)));
        for (size_t i = 0; i < this->keys_count; ++i) {
            h[i] = first_hash(keys[i].c_str(), keys[i].size());
        }
        hash_gen(h);
        free(h);
    }

    /** Builds a RecSplit instance using a given list of 128-bit hashes and bucket size.
     *
     * **Warning**: duplicate keys will cause this method to never return.
     *
     * Note that this constructor is mainly useful for benchmarking.
     * @param keys a vector of 128-bit hashes.
     * @param bucket_size the desired bucket size; typical sizes go from
     * 100 to 2000, with smaller buckets giving slightly larger but faster
     * functions.
     */
    RecSplit(vector<hash128_t>& keys, const size_t _bucket_size) {
        this->bucket_size = _bucket_size;
        this->keys_count = keys.size();
        hash_gen(&keys[0]);
    }

    /** Builds a RecSplit instance using a list of keys returned by a stream and bucket size.
     *
     * **Warning**: duplicate keys will cause this method to never return.
     *
     * @param input an open input stream returning a list of keys, one per line.
     * @param bucket_size the desired bucket size.
     */
    RecSplit(ifstream& input, const size_t _bucket_size) {
        this->bucket_size = _bucket_size;
        vector<hash128_t> h;
        for (string key; getline(input, key);) h.push_back(first_hash(key.c_str(), key.size()));
        this->keys_count = h.size();
        hash_gen(&h[0]);
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
            const auto d = reader.readNext(golomb_param(m));
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
            const auto d = reader.readNext(golomb_param(m));
            const size_t hmod = remap16(remix(hash.second + d + start_seed[level]), m);

            const int part = uint16_t(hmod) / lower_aggr;
            m = min(lower_aggr, m - part * lower_aggr);
            cum_keys += lower_aggr * part;
            if (part) reader.skipSubtree(skip_nodes(lower_aggr) * part, skip_bits(lower_aggr) * part);
            level++;
        }

        if (m > _leaf) {
            const auto d = reader.readNext(golomb_param(m));
            const size_t hmod = remap16(remix(hash.second + d + start_seed[level]), m);

            const int part = uint16_t(hmod) / _leaf;
            m = min(_leaf, m - part * _leaf);
            cum_keys += _leaf * part;
            if (part) reader.skipSubtree(part, skip_bits(_leaf) * part);
            level++;
        }

        const auto b = reader.readNext(golomb_param(m));
        return cum_keys + remap16(remix(hash.second + b + start_seed[level]), m);
    }

    /** Returns the value associated with the given key.
     *
     * @param key a key.
     * @return the associated value.
     */
    size_t operator()(const string& key) { return operator()(first_hash(key.c_str(), key.size())); }

    /** Returns the number of keys used to build this RecSplit instance. */
    inline size_t size() { return this->keys_count; }

  private:
    // Maps a 128-bit to a bucket using the first 64-bit half.
    inline uint64_t hash128_to_bucket(const hash128_t& hash) const { return remap128(hash.first, nbuckets); }

    // Computes and stores the splittings and bijections of a bucket.
    void recSplit(vector<uint64_t>& bucket, typename RiceBitVector<AT>::Builder& builder, vector<uint32_t>& unary) {
        const auto m = bucket.size();
        vector<uint64_t> temp(m);
        recSplit(bucket, temp, 0, bucket.size(), builder, unary, 0);
    }

    void recSplit(vector<uint64_t>& bucket, vector<uint64_t>& temp, size_t start, size_t end, typename RiceBitVector<AT>::Builder& builder, vector<uint32_t>& unary, const int level) {
        static const array<uint8_t, MAX_LEAF_SIZE> bij_midstop = fill_bij_midstop();
        const auto m = end - start;
        assert(m > 1);
        uint64_t x = start_seed[level];

        if (m <= _leaf) {
#ifdef MORESTATS
            sum_depths += m * level;
            auto start_time = high_resolution_clock::now();
#endif
            uint32_t mask;
            const uint32_t found = (1 << m) - 1;
            if constexpr (_leaf <= 8) {
                for (;;) {
                    mask = 0;
                    for (size_t i = start; i < end; i++) mask |= uint32_t(1) << remap16(remix(bucket[i] + x), m);
#ifdef MORESTATS
                    num_bij_evals[m] += m;
#endif
                    if (mask == found) break;
                    x++;
                }
            } else {
                const size_t midstop = bij_midstop[m];
                for (;;) {
                    mask = 0;
                    size_t i;
                    for (i = start; i < start + midstop; i++) mask |= uint32_t(1) << remap16(remix(bucket[i] + x), m);
#ifdef MORESTATS
                    num_bij_evals[m] += midstop;
#endif
                    if (nu(mask) == midstop) {
                        for (; i < end; i++) mask |= uint32_t(1) << remap16(remix(bucket[i] + x), m);
#ifdef MORESTATS
                        num_bij_evals[m] += m - midstop;
#endif
                        if (mask == found) break;
                    }
                    x++;
                }
            }
#ifdef MORESTATS
            time_bij += duration_cast<nanoseconds>(high_resolution_clock::now() - start_time).count();
#endif
            x -= start_seed[level];
            const auto log2golomb = golomb_param(m);
            builder.appendFixed(x, log2golomb);
            unary.push_back(x >> log2golomb);
#ifdef MORESTATS
            bij_count[m]++;
            num_bij_trials[m] += x + 1;
            bij_unary += 1 + (x >> log2golomb);
            bij_fixed += log2golomb;

            min_bij_code = min(min_bij_code, x);
            max_bij_code = max(max_bij_code, x);
            sum_bij_codes += x;

            auto b = bij_memo_golomb[m];
            auto log2b = lambda(b);
            bij_unary_golomb += x / b + 1;
            bij_fixed_golomb += x % b < ((1 << log2b + 1) - b) ? log2b : log2b + 1;
#endif
        } else {
#ifdef MORESTATS
            auto start_time = high_resolution_clock::now();
#endif
            if (m > upper_aggr) {  // fanout = 2
                const size_t split = ((uint16_t(m / 2 + upper_aggr - 1) / upper_aggr)) * upper_aggr;

                size_t count[2];
                for (;;) {
                    count[0] = 0;
                    for (size_t i = start; i < end; i++) {
                        count[remap16(remix(bucket[i] + x), m) >= split]++;
#ifdef MORESTATS
                        ++num_split_evals;
#endif
                    }
                    if (count[0] == split) break;
                    x++;
                }

                count[0] = 0;
                count[1] = split;
                for (size_t i = start; i < end; i++) {
                    temp[count[remap16(remix(bucket[i] + x), m) >= split]++] = bucket[i];
                }
                copy(&temp[0], &temp[m], &bucket[start]);
                x -= start_seed[level];
                const auto log2golomb = golomb_param(m);
                builder.appendFixed(x, log2golomb);
                unary.push_back(x >> log2golomb);

#ifdef MORESTATS
                time_split[min(MAX_LEVEL_TIME, level)] += duration_cast<nanoseconds>(high_resolution_clock::now() - start_time).count();
#endif
                recSplit(bucket, temp, start, start + split, builder, unary, level + 1);
                if (m - split > 1) recSplit(bucket, temp, start + split, end, builder, unary, level + 1);
#ifdef MORESTATS
                else
                    sum_depths += level;
#endif
            } else if (m > lower_aggr) {  // 2nd aggregation level
                const size_t fanout = uint16_t(m + lower_aggr - 1) / lower_aggr;
                size_t* count = new size_t[fanout];  // Note that we never read count[fanout-1]
                for (;;) {
                    memset(count, 0, fanout * sizeof(size_t));
                    for (size_t i = start; i < end; i++) {
                        count[uint16_t(remap16(remix(bucket[i] + x), m)) / lower_aggr]++;
#ifdef MORESTATS
                        ++num_split_evals;
#endif
                    }
                    size_t broken = 0;
                    for (size_t i = 0; i < fanout - 1; i++) broken |= count[i] - lower_aggr;
                    if (!broken) break;
                    x++;
                }

                for (size_t i = 0, c = 0; i < fanout; i++, c += lower_aggr) count[i] = c;
                for (size_t i = start; i < end; i++) {
                    temp[count[uint16_t(remap16(remix(bucket[i] + x), m)) / lower_aggr]++] = bucket[i];
                }
                copy(&temp[0], &temp[m], &bucket[start]);
                delete[] count;

                x -= start_seed[level];
                const auto log2golomb = golomb_param(m);
                builder.appendFixed(x, log2golomb);
                unary.push_back(x >> log2golomb);

#ifdef MORESTATS
                time_split[min(MAX_LEVEL_TIME, level)] += duration_cast<nanoseconds>(high_resolution_clock::now() - start_time).count();
#endif
                size_t i;
                for (i = 0; i < m - lower_aggr; i += lower_aggr) {
                    recSplit(bucket, temp, start + i, start + i + lower_aggr, builder, unary, level + 1);
                }
                if (m - i > 1) recSplit(bucket, temp, start + i, end, builder, unary, level + 1);
#ifdef MORESTATS
                else
                    sum_depths += level;
#endif
            } else {  // First aggregation level, m <= lower_aggr
                const size_t fanout = uint16_t(m + _leaf - 1) / _leaf;
                size_t* count = new size_t[fanout];  // Note that we never read count[fanout-1]
                for (;;) {
                    memset(count, 0, fanout * sizeof(size_t));
                    for (size_t i = start; i < end; i++) {
                        count[uint16_t(remap16(remix(bucket[i] + x), m)) / _leaf]++;
#ifdef MORESTATS
                        ++num_split_evals;
#endif
                    }
                    size_t broken = 0;
                    for (size_t i = 0; i < fanout - 1; i++) broken |= count[i] - _leaf;
                    if (!broken) break;
                    x++;
                }
                for (size_t i = 0, c = 0; i < fanout; i++, c += _leaf) count[i] = c;
                for (size_t i = start; i < end; i++) {
                    temp[count[uint16_t(remap16(remix(bucket[i] + x), m)) / _leaf]++] = bucket[i];
                }
                copy(&temp[0], &temp[m], &bucket[start]);
                delete[] count;

                x -= start_seed[level];
                const auto log2golomb = golomb_param(m);
                builder.appendFixed(x, log2golomb);
                unary.push_back(x >> log2golomb);

#ifdef MORESTATS
                time_split[min(MAX_LEVEL_TIME, level)] += duration_cast<nanoseconds>(high_resolution_clock::now() - start_time).count();
#endif
                size_t i;
                for (i = 0; i < m - _leaf; i += _leaf) {
                    recSplit(bucket, temp, start + i, start + i + _leaf, builder, unary, level + 1);
                }
                if (m - i > 1) recSplit(bucket, temp, start + i, end, builder, unary, level + 1);
#ifdef MORESTATS
                else
                    sum_depths += level;
#endif
            }

#ifdef MORESTATS
            ++split_count;
            num_split_trials += x + 1;
            double e_trials = 1;
            size_t aux = m;
            SplitStrat strat{m};
            auto v = strat.begin();
            for (int i = 0; i < strat.fanout(); ++i, ++v) {
                e_trials *= pow((double)m / *v, *v);
                for (size_t j = *v; j > 0; --j, --aux) {
                    e_trials *= (double)j / aux;
                }
            }
            expected_split_trials += (size_t)e_trials;
            expected_split_evals += (size_t)e_trials * m;
            const auto log2golomb = golomb_param(m);
            split_unary += 1 + (x >> log2golomb);
            split_fixed += log2golomb;

            min_split_code = min(min_split_code, x);
            max_split_code = max(max_split_code, x);
            sum_split_codes += x;

            auto b = split_golomb_b<LEAF_SIZE>(m);
            auto log2b = lambda(b);
            split_unary_golomb += x / b + 1;
            split_fixed_golomb += x % b < ((1ULL << log2b + 1) - b) ? log2b : log2b + 1;
#endif
        }
    }

    void hash_gen(hash128_t* hashes) {
#ifdef MORESTATS
        time_bij = 0;
        memset(time_split, 0, sizeof time_split);
        split_unary = split_fixed = 0;
        bij_unary = bij_fixed = 0;
        min_split_code = 1UL << 63;
        max_split_code = sum_split_codes = 0;
        min_bij_code = 1UL << 63;
        max_bij_code = sum_bij_codes = 0;
        sum_depths = 0;
        size_t minsize = keys_count, maxsize = 0;
        double ub_split_bits = 0, ub_bij_bits = 0;
        double ub_split_evals = 0, ub_bij_evals = 0;
#endif

#ifndef __SIZEOF_INT128__
        if (keys_count > (1ULL << 32)) {
            fprintf(stderr, "For more than 2^32 keys, you need 128-bit integer support.\n");
            abort();
        }
#endif
        nbuckets = max(1, (keys_count + bucket_size - 1) / bucket_size);
        auto bucket_size_acc = vector<int64_t>(nbuckets + 1);
        auto bucket_pos_acc = vector<int64_t>(nbuckets + 1);

        sort(hashes, hashes + keys_count, [this](const hash128_t& a, const hash128_t& b) { return hash128_to_bucket(a) < hash128_to_bucket(b); });
        typename RiceBitVector<AT>::Builder builder;

        bucket_size_acc[0] = bucket_pos_acc[0] = 0;
        for (size_t i = 0, last = 0; i < nbuckets; i++) {
            vector<uint64_t> bucket;
            for (; last < keys_count && hash128_to_bucket(hashes[last]) == i; last++) bucket.push_back(hashes[last].second);

            const size_t s = bucket.size();
            bucket_size_acc[i + 1] = bucket_size_acc[i] + s;
            if (bucket.size() > 1) {
                vector<uint32_t> unary;
                recSplit(bucket, builder, unary);
                builder.appendUnaryAll(unary);
            }
            bucket_pos_acc[i + 1] = builder.getBits();
#ifdef MORESTATS
            auto upper_leaves = (s + _leaf - 1) / _leaf;
            auto upper_height = ceil(log(upper_leaves) / log(2));  // TODO: check
            auto upper_s = _leaf * pow(2, upper_height);
            ub_split_bits += (double)upper_s / (_leaf * 2) * log2(2 * M_PI * _leaf) - .5 * log2(2 * M_PI * upper_s);
            ub_bij_bits += upper_leaves * _leaf * (log2e - .5 / _leaf * log2(2 * M_PI * _leaf));
            ub_split_evals += 4 * upper_s * sqrt(pow(2 * M_PI * upper_s, 2 - 1) / pow(2, 2));
            minsize = min(minsize, s);
            maxsize = max(maxsize, s);
#endif
        }
        builder.appendFixed(1, 1);  // Sentinel (avoids checking for parts of size 1)
        descriptors = builder.build();
        ef = DoubleEF<AT>(vector<uint64_t>(bucket_size_acc.begin(), bucket_size_acc.end()), vector<uint64_t>(bucket_pos_acc.begin(), bucket_pos_acc.end()));

#ifdef STATS
        // Evaluation purposes only
        double ef_sizes = (double)ef.bitCountCumKeys() / keys_count;
        double ef_bits = (double)ef.bitCountPosition() / keys_count;
        double rice_desc = (double)builder.getBits() / keys_count;
        printf("Elias-Fano cumul sizes:  %f bits/bucket\n", (double)ef.bitCountCumKeys() / nbuckets);
        printf("Elias-Fano cumul bits:   %f bits/bucket\n", (double)ef.bitCountPosition() / nbuckets);
        printf("Elias-Fano cumul sizes:  %f bits/key\n", ef_sizes);
        printf("Elias-Fano cumul bits:   %f bits/key\n", ef_bits);
        printf("Rice-Golomb descriptors: %f bits/key\n", rice_desc);
        printf("Total bits:              %f bits/key\n", ef_sizes + ef_bits + rice_desc);
#endif
#ifdef MORESTATS

        printf("\n");
        printf("Min bucket size: %lu\n", minsize);
        printf("Max bucket size: %lu\n", maxsize);

        printf("\n");
        printf("Bijections: %13.3f ms\n", time_bij * 1E-6);
        for (int i = 0; i < MAX_LEVEL_TIME; i++) {
            if (time_split[i] > 0) {
                printf("Split level %d: %10.3f ms\n", i, time_split[i] * 1E-6);
            }
        }

        uint64_t fact = 1, tot_bij_count = 0, tot_bij_evals;
        printf("\n");
        printf("Bij               count              trials                 exp               evals                 exp           tot evals\n");
        for (int i = 0; i < MAX_LEAF_SIZE; i++) {
            if (num_bij_trials[i] != 0) {
                tot_bij_count += bij_count[i];
                tot_bij_evals += num_bij_evals[i];
                printf("%-3d%20d%20.2f%20.2f%20.2f%20.2f%20lld\n", i, bij_count[i], (double)num_bij_trials[i] / bij_count[i], pow(i, i) / fact, (double)num_bij_evals[i] / bij_count[i],
                       (_leaf <= 8 ? i : bij_midstop[i]) * pow(i, i) / fact, num_bij_evals[i]);
            }
            fact *= (i + 1);
        }

        printf("\n");
        printf("Split count:       %16zu\n", split_count);

        printf("Total split evals: %16lld\n", num_split_evals);
        printf("Total bij evals:   %16lld\n", tot_bij_evals);
        printf("Total evals:       %16lld\n", num_split_evals + tot_bij_evals);

        printf("\n");
        printf("Average depth:        %f\n", (double)sum_depths / keys_count);
        printf("\n");
        printf("Trials per split:     %16.3f\n", (double)num_split_trials / split_count);
        printf("Exp trials per split: %16.3f\n", (double)expected_split_trials / split_count);
        printf("Evals per split:      %16.3f\n", (double)num_split_evals / split_count);
        printf("Exp evals per split:  %16.3f\n", (double)expected_split_evals / split_count);

        printf("\n");
        printf("Unary bits per bij: %10.5f\n", (double)bij_unary / tot_bij_count);
        printf("Fixed bits per bij: %10.5f\n", (double)bij_fixed / tot_bij_count);
        printf("Total bits per bij: %10.5f\n", (double)(bij_unary + bij_fixed) / tot_bij_count);

        printf("\n");
        printf("Unary bits per split: %10.5f\n", (double)split_unary / split_count);
        printf("Fixed bits per split: %10.5f\n", (double)split_fixed / split_count);
        printf("Total bits per split: %10.5f\n", (double)(split_unary + split_fixed) / split_count);
        printf("Total bits per key:   %10.5f\n", (double)(bij_unary + bij_fixed + split_unary + split_fixed) / keys_count);

        printf("\n");
        printf("Unary bits per bij (Golomb): %10.5f\n", (double)bij_unary_golomb / tot_bij_count);
        printf("Fixed bits per bij (Golomb): %10.5f\n", (double)bij_fixed_golomb / tot_bij_count);
        printf("Total bits per bij (Golomb): %10.5f\n", (double)(bij_unary_golomb + bij_fixed_golomb) / tot_bij_count);

        printf("\n");
        printf("Unary bits per split (Golomb): %10.5f\n", (double)split_unary_golomb / split_count);
        printf("Fixed bits per split (Golomb): %10.5f\n", (double)split_fixed_golomb / split_count);
        printf("Total bits per split (Golomb): %10.5f\n", (double)(split_unary_golomb + split_fixed_golomb) / split_count);
        printf("Total bits per key (Golomb):   %10.5f\n", (double)(bij_unary_golomb + bij_fixed_golomb + split_unary_golomb + split_fixed_golomb) / keys_count);

        printf("\n");

        printf("Total split bits        %16.3f\n", (double)split_fixed + split_unary);
        printf("Upper bound split bits: %16.3f\n", ub_split_bits);
        printf("Total bij bits:         %16.3f\n", (double)bij_fixed + bij_unary);
        printf("Upper bound bij bits:   %16.3f\n\n", ub_bij_bits);
#endif
    }

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

}  // namespace sux::function
