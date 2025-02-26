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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#if defined(__clang__)
#pragma GCC diagnostic ignored "-Winvalid-constexpr"
#endif /* defined(__clang__) */
#pragma GCC diagnostic ignored "-Wsign-compare"

#include <silkworm/infra/concurrency/thread_pool.hpp>

#include "rec_split.hpp"

// Check if the vector contains duplicates without altering the original vector order
// Used here to check the keys vector (whose elements are related to the elements of values vector at the same index)
template <typename T>
bool contains_duplicate(const std::vector<T>& items) {
    // Create an index vector
    std::vector<size_t> indices(items.size());
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

namespace silkworm::snapshots::rec_split {

//! The recsplit parallel building strategy
template <size_t LEAF_SIZE>
struct RecSplit<LEAF_SIZE>::ParallelBuildingStrategy : public BuildingStrategy {
    explicit ParallelBuildingStrategy(ThreadPool& tp) : thread_pool_{tp} {
    }

  protected:
    class Bucket {
      public:
        explicit Bucket(size_t bucket_size) {
            keys_.reserve(bucket_size);
            values_.reserve(bucket_size);
        }
        Bucket(const Bucket&) = delete;
        Bucket(Bucket&&) noexcept = default;

        void clear() {
            keys_.clear();
            values_.clear();
            gr_builder_.clear();
            index_ofs_.clear();
        }

      private:
        friend class RecSplit;

        //! 64-bit fingerprints of keys in the current bucket accumulated before the recsplit is performed for that bucket
        std::vector<uint64_t> keys_;  // mike: current_bucket_;  -> keys_

        //! Index offsets for the current bucket
        std::vector<uint64_t> values_;  // mike: current_bucket_offsets_; -> values_

        //! Helper to build GR codes of splitting and bijection indices, local to current bucket
        GolombRiceVector::LazyBuilder gr_builder_;

        //! The local max index used in Golomb parameter array
        uint16_t golomb_param_max_index_{0};

        //! Helper index output stream
        std::stringstream index_ofs_{std::ios::in | std::ios::out | std::ios::binary};
    };

    void setup(const RecSplitSettings& settings, size_t bucket_count) override {
        double_enum_index_ = settings.double_enum_index;
        bucket_count_ = bucket_count;

        // Prepare buckets
        buckets_.reserve(bucket_count);
        for (int i = 0; i < bucket_count; ++i) {
            buckets_.emplace_back(settings.bucket_size);
        }
        if (double_enum_index_) {
            offsets_.reserve(settings.keys_count);
        }
    }

    void add_key(uint64_t bucket_id, uint64_t bucket_key, uint64_t offset) override {
        ensure(bucket_id < buckets_.size(), "bucket_id out of range");

        if (keys_added_ % 100'000 == 0) {
            SILK_TRACE << "[index] add key hash: bucket_id=" << bucket_id << " bucket_key=" << bucket_key << " offset=" << offset;
        }

        max_offset_ = std::max(max_offset_, offset);

        Bucket& bucket = buckets_[bucket_id];

        if (double_enum_index_) {
            offsets_.push_back(offset);

            auto current_key_count = keys_added_;

            bucket.keys_.emplace_back(bucket_key);
            bucket.values_.emplace_back(current_key_count);
        } else {
            bucket.keys_.emplace_back(bucket_key);
            bucket.values_.emplace_back(offset);
        }

        ++keys_added_;
    }

    bool build_mph_index(
        std::ofstream& index_output_stream,
        GolombRiceVector& golomb_rice_codes,
        uint16_t& golomb_param_max_index,
        DoubleEliasFano& double_ef_index,
        uint8_t bytes_per_record) override {
        // Find splitting trees for each bucket
        std::atomic_bool collision{false};
        for (auto& bucket : buckets_) {
            thread_pool_.push_task([&]() noexcept(false) {
                if (collision) return;  // skip work if collision detected
                bool local_collision = recsplit_bucket(bucket, bytes_per_record);
                if (local_collision) collision = true;
            });
        }
        thread_pool_.wait_for_tasks();
        if (collision) {
            SILK_WARN << "[index] collision detected";
            return true;
        }

        // Store prefix sums of bucket sizes and bit positions
        std::vector<int64_t> bucket_size_accumulator(this->bucket_count_ + 1);      // accumulator for size of every bucket
        std::vector<int64_t> bucket_position_accumulator(this->bucket_count_ + 1);  // accumulator for position of every bucket in the encoding of the hash function

        bucket_size_accumulator[0] = bucket_position_accumulator[0] = 0;
        for (size_t i = 0; i < bucket_count_; ++i) {
            bucket_size_accumulator[i + 1] = bucket_size_accumulator[i] + buckets_[i].keys_.size();

            // auto* underlying_buffer = buckets_[i].index_ofs_.rdbuf();
            // if (!is_empty(underlying_buffer))
            //     index_output_stream << underlying_buffer;
            char byte{0};
            while (buckets_[i].index_ofs_.get(byte)) {  // maybe it is better to avoid this and use a buffer in place of index_ofs_
                index_output_stream.put(byte);
            }
            // index_output_stream << buckets_[i].index_ofs_.rdbuf();  // better but fails when rdbuf() is empty

            if (buckets_[i].keys_.size() > 1) {
                buckets_[i].gr_builder_.append_to(gr_builder_);
            }

            bucket_position_accumulator[i + 1] = gr_builder_.get_bits();

            SILKWORM_ASSERT(bucket_size_accumulator[i + 1] >= bucket_size_accumulator[i]);
            SILKWORM_ASSERT(bucket_position_accumulator[i + 1] >= bucket_position_accumulator[i]);

            golomb_param_max_index = std::max(golomb_param_max_index, buckets_[i].golomb_param_max_index_);
        }

        gr_builder_.append_fixed(1, 1);  // Sentinel (avoids checking for parts of size 1)

        // Concatenate the representation of each bucket
        golomb_rice_codes = gr_builder_.build();

        // Construct double Elias-Fano index for bucket cumulative keys and bit positions
        std::vector<uint64_t> cumulative_keys{bucket_size_accumulator.begin(), bucket_size_accumulator.end()};
        std::vector<uint64_t> positions(bucket_position_accumulator.begin(), bucket_position_accumulator.end());
        double_ef_index.build(cumulative_keys, positions);

        return false;  // no collision
    }

    void build_enum_index(std::unique_ptr<EliasFanoBuilder>& ef_offsets) override {
        // Build Elias-Fano index for offsets (if any)
        std::sort(offsets_.begin(), offsets_.end());
        ef_offsets = std::make_unique<EliasFanoBuilder>(keys_added_, max_offset_);
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
            if (contains_duplicate(bucket.keys_)) {
                SILK_TRACE << "collision detected";
                return true;
            }

            std::vector<uint64_t> buffer_keys;     // temporary buffer for keys
            std::vector<uint64_t> buffer_offsets;  // temporary buffer for offsets
            buffer_keys.resize(bucket.keys_.size());
            buffer_offsets.resize(bucket.values_.size());

            RecSplit<LEAF_SIZE>::recsplit(
                bucket.keys_, bucket.values_, buffer_keys, buffer_offsets, bucket.gr_builder_,
                bucket.index_ofs_, bucket.golomb_param_max_index_, bytes_per_record);
        } else {
            for (const auto offset : bucket.values_) {
                Bytes uint64_buffer(8, '\0');
                endian::store_big_u64(uint64_buffer.data(), offset);
                bucket.index_ofs_.write(reinterpret_cast<const char*>(uint64_buffer.data()), 8);
                SILK_TRACE << "[index] written offset: " << offset;
            }
        }

        return false;
    }

    void clear() override {
        offsets_.clear();
        for (auto& bucket : buckets_) {
            bucket.clear();
        }
        keys_added_ = 0;
        max_offset_ = 0;
    }

    uint64_t keys_added() override {
        return keys_added_;
    }

    uint64_t max_offset() override {
        return max_offset_;
    }

    //! The thread pool used for parallel processing
    ThreadPool& thread_pool_;

    //! Flag indicating if two-level index "recsplit -> enum" + "enum -> offset" is required
    bool double_enum_index_{false};

    //! Maximum value of offset used to decide how many bytes to use for Elias-Fano encoding
    uint64_t max_offset_{0};

    //! The number of keys currently added
    uint64_t keys_added_{0};

    //! The number of buckets for this Recsplit algorithm instance
    size_t bucket_count_{0};

    //! The buckets of the RecSplit algorithm
    std::vector<Bucket> buckets_;

    //! The offset collector for Elias-Fano encoding of "enum -> offset" index
    std::vector<uint64_t> offsets_;

    //! Helper to build GR codes of splitting and bijection indices
    GolombRiceBuilder gr_builder_;
};

inline auto par_build_strategy(ThreadPool& tp) {
    return std::make_unique<RecSplit8::ParallelBuildingStrategy>(tp);
}

/*
 Example usage:
    RecSplit8 recsplit{RecSplitSettings{}, par_build_strategy(thread_pool)};
    auto collision = recsplit.build();
*/

}  // namespace silkworm::snapshots::rec_split

#pragma GCC diagnostic pop
