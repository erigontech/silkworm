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
#include <silkworm/node/recsplit/rec_split.hpp>
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

namespace silkworm::succinct::parallel {

template <std::size_t LEAF_SIZE>
struct ParallelBuildingStrategy: public BuildingStrategy<LEAF_SIZE> {

    struct Bucket {
        Bucket(uint64_t bucket_id, std::size_t bucket_size) : bucket_id_{bucket_id} {
            keys_.reserve(bucket_size);
            values_.reserve(bucket_size);
        }
        Bucket(const Bucket&) = delete;
        Bucket(Bucket&&) noexcept = default;

        //! Identifier of the current bucket being accumulated
        uint64_t bucket_id_{0};

        //! 64-bit fingerprints of keys in the current bucket accumulated before the recsplit is performed for that bucket
        std::vector<uint64_t> keys_;  // mike: current_bucket_;  -> keys_

        //! Index offsets for the current bucket
        std::vector<uint64_t> values_;  // mike: current_bucket_offsets_; -> values_

        //! Helper to build GR codes of splitting and bijection indices, local to current bucket
        GolombRiceVector::LazyBuilder gr_builder_;

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

    //! The buckets of the RecSplit algorithm
    std::vector<Bucket> buckets_;

    //! The offset collector for Elias-Fano encoding of "enum -> offset" index
    std::vector<uint64_t> offsets_;

    //! Helper to build GR codes of splitting and bijection indices
    GolombRiceBuilder gr_builder_;

    //! Minimum delta for Elias-Fano encoding of "enum -> offset" index
    // uint64_t min_delta_{0};  // unused

    //! Last previously added offset (for calculating minimum delta for Elias-Fano encoding of "enum -> offset" index)
    // uint64_t previous_offset_{0};  // unused

    ThreadPool* thread_pool_{nullptr};

    ParallelBuildingStrategy(ThreadPool& thread_pool) : thread_pool_{&thread_pool} {
    }

    virtual void params(std::size_t bucket_size, std::size_t bucket_count, std::size_t key_count,
                        std::size_t, bool double_enum_index) override {
        // Prepare backets
        buckets_.reserve(bucket_count);
        for (int i = 0; i < bucket_count; i++)
            buckets_.emplace_back(i, bucket_size);
        if (double_enum_index)
            offsets_.reserve(key_count);
    }

    void add_key(uint64_t bucket_id, uint64_t bucket_key, uint64_t offset) {
        ensure(bucket_id < buckets_.size(), "bucket_id out of range");

        if (this->keys_added_ % 100'000 == 0) {
            SILK_DEBUG << "[index] add key hash: bucket_id=" << bucket_id << " bucket_key=" << bucket_key << " offset=" << offset;
        }

        if (offset > this->max_offset_) {
            this->max_offset_ = offset;
        }

        // if (keys_added_ > 0) {  // unused
        //     const auto delta = offset - previous_offset_;
        //     if (keys_added_ == 1 || delta < min_delta_) {
        //         min_delta_ = delta;
        //     }
        // }

        Bucket& bucket = buckets_[bucket_id];

        if (this->double_enum_index_) {
            offsets_.push_back(offset);

            auto current_key_count = this->keys_added_;

            bucket.keys_.emplace_back(bucket_key);
            bucket.values_.emplace_back(current_key_count);
        } else {
            bucket.keys_.emplace_back(bucket_key);
            bucket.values_.emplace_back(offset);
        }

        this->keys_added_++;
        // previous_offset_ = offset;
    }

  protected:
    bool build_mph(std::ofstream& index_output_stream, GolombRiceVector golomb_rice_codes, DoubleEliasFano& double_ef_index, uint8_t bytes_per_record) {
        // SILK_INFO << "par-ver - GEN - Base data ID: " << base_data_id_ << " key count: " << key_count_
        //          << " keys_added: " << keys_added_ << " bytes per record: " << int(bytes_per_record_)
        //          << " record mask: " << record_mask_ << " max_hoffset: " << max_offset_ << " bucket_count: " << bucket_count_;

        // Find splitting trees for each bucket
        std::atomic_bool collision{false};
        for (auto& bucket : buckets_) {
            thread_pool_->push_task([&]() noexcept(false) {
                if (collision) return;  // skip work if collision detected
                bool local_collision = recsplit_bucket(bucket, bytes_per_record);
                if (local_collision) collision = true;
                // SILK_INFO << "processed " << bucket.bucket_id_;
            });
        }
        thread_pool_->wait_for_tasks();
        if (collision) {
            SILK_WARN << "[index] collision detected";
            return true;
        }

        // Store prefix sums of bucket sizes and bit positions
        std::vector<int64_t> bucket_size_accumulator_(this->bucket_count_ + 1);      // accumulator for size of every bucket
        std::vector<int64_t> bucket_position_accumulator_(this->bucket_count_ + 1);  // accumulator for position of every bucket in the encoding of the hash function

        bucket_size_accumulator_[0] = bucket_position_accumulator_[0] = 0;
        for (size_t i = 0; i < this->bucket_count_; i++) {
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

            this->golomb_param_max_index_ = std::max(this->golomb_param_max_index_, buckets_[i].golomb_param_max_index_);
        }

        // SILK_INFO << "PROBE par-vers - sizes: " << prettyPrint(bucket_size_accumulator_);
        // SILK_INFO << "PROBE par-vers - positions: " << prettyPrint(bucket_position_accumulator_);

        gr_builder_.append_fixed(1, 1);  // Sentinel (avoids checking for parts of size 1)

        // Concatenate the representation of each bucket
        golomb_rice_codes = gr_builder_.build();

        // SILK_INFO << "PROBE par-vers - golomb_rice_codes: size " << golomb_rice_codes_.size() << ", content " << golomb_rice_codes_;

        // Construct double Elias-Fano index for bucket cumulative keys and bit positions
        std::vector<uint64_t> cumulative_keys{bucket_size_accumulator_.begin(), bucket_size_accumulator_.end()};
        std::vector<uint64_t> positions(bucket_position_accumulator_.begin(), bucket_position_accumulator_.end());
        double_ef_index.build(cumulative_keys, positions);

        return false;  // no collision
    }

    void build_double_enum_index(std::unique_ptr<EliasFano>& ef_offsets) {
        // Build Elias-Fano index for offsets (if any)
        std::sort(offsets_.begin(), offsets_.end());
        ef_offsets = std::make_unique<EliasFano>(this->keys_added_, this->max_offset_);
        for (auto offset : offsets_) {
            ef_offsets->add_offset(offset);
        }
        ef_offsets->build();
    }

    //! Compute and store the splittings and bijections of the current bucket
    // It would be better to make this function a member of Bucket
    static bool recsplit_bucket(Bucket& bucket, uint8_t bytes_per_record) {
        // Sets of size 0 and 1 are not further processed, just write them to index
        if (bucket.keys_.size() > 1) {
            if (containsDuplicate(bucket.keys_)) {
                SILK_TRACE << "collision detected";
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

    void clear() {
        offsets_.clear();
        for (auto& bucket : buckets_) {
            bucket.clear();
        }
        this->keys_added_ = 0;
        this->max_offset_ = 0;
    }

};


constexpr std::size_t kLeafSize{8};
using RecSplit8 = RecSplit<kLeafSize>;

using RecSplitIndex = RecSplit8;

using ParallelBuildingStrategy8 = ParallelBuildingStrategy<kLeafSize>;

/*
   RecSplit8 recsplit{settings, new ParallelBuildingStrategy8(thread_pool)};
   auto collision = recsplit.build();
 */

}  // namespace silkworm::succinct::parallel

#pragma GCC diagnostic pop
