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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#if defined(__clang__)
#pragma GCC diagnostic ignored "-Winvalid-constexpr"
#endif /* defined(__clang__) */
#pragma GCC diagnostic ignored "-Wsign-compare"

#include <silkworm/infra/concurrency/thread_pool.hpp>
#include <silkworm/node/recsplit/rec_split.hpp>

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

// merge_sorted_vectors merges multiple sorted vectors into a single sorted vector
// The input vectors must be sorted in ascending order
// The output vector is sorted in ascending order
// The input vectors must not contain duplicates
// The output vector does not contain duplicates
// The input can be constructed moving all the vectors in all_vector
// otherwise we have to use an all_vector made by std::vector<std::reference_wrapper<const std::vector<int>>>
template <typename T>
std::vector<T> merge_sorted_vectors(const std::vector<std::vector<T>>& all_vectors) {
    // Calculate total size for reservation
    size_t total_size = 0;
    for (const auto& vec : all_vectors) {
        total_size += vec.size();
    }

    std::vector<T> result;
    result.reserve(total_size);  // Reserve space

    struct Element {
        T val;
        size_t vec_index;   // Index of the original vector
        size_t next_index;  // Index of the next element in the original vector

        // Comparator for min heap
        bool operator>(const Element& other) const {
            return val > other.val;
        }
    };

    std::priority_queue<Element, std::vector<Element>, std::greater<>> min_heap;
    for (size_t i = 0; i < all_vectors.size(); ++i) {
        if (!all_vectors[i].empty()) {
            min_heap.push({all_vectors[i][0], i, 1});
        }
    }

    while (!min_heap.empty()) {
        Element current = min_heap.top();
        min_heap.pop();

        result.push_back(current.val);

        if (current.next_index < all_vectors[current.vec_index].size()) {
            min_heap.push({all_vectors[current.vec_index][current.next_index], current.vec_index, current.next_index + 1});
        }
    }

    return result;
}

// set_max sets the value of an atomic var to a new value v if v is greater than the current value
template <typename T>
void set_max(std::atomic<T>& atom, T v) {
    T current = atom.load();
    while (v > current && !atom.compare_exchange_weak(current, v))
        ;
}


namespace silkworm::succinct {

//! The recsplit parallel building strategy
template <std::size_t LEAF_SIZE>
struct RecSplit<LEAF_SIZE>::ParallelBuildingStrategy : public BuildingStrategy {
    explicit ParallelBuildingStrategy(ThreadPool& tp) : thread_pool_{tp} {
    }

  protected:
    struct Bucket {
        Bucket(uint64_t bucket_id, std::size_t bucket_size, bool double_enum)
            : bucket_id_{bucket_id}, double_enum_{double_enum}, mutex_{new std::mutex} {
            keys_.reserve(bucket_size);
            values_.reserve(bucket_size);
            if (double_enum_) offsets_.reserve(bucket_size);
        }
        Bucket(const Bucket&) = delete;

        Bucket(Bucket&& other) noexcept
            : bucket_id_{other.bucket_id_}, keys_{std::move(other.keys_)}, values_{std::move(other.values_)},
              offsets_{std::move(other.offsets_)}, gr_builder_{std::move(other.gr_builder_)},
              double_enum_{other.double_enum_}, index_ofs{std::move(other.index_ofs)}, mutex_{other.mutex_} {
            other.mutex_ = nullptr;
        }

        ~Bucket() {
            delete mutex_;
        }

        void add_key(uint64_t bucket_key, uint64_t offset, uint64_t ordinal) {
            std::lock_guard<std::mutex> lock{*mutex_};

            if (double_enum_) {
                offsets_.push_back(offset);

                keys_.emplace_back(bucket_key);
                values_.emplace_back(ordinal);
            } else {
                keys_.emplace_back(bucket_key);
                values_.emplace_back(offset);
            }
        }

        //! Identifier of the current bucket being accumulated
        uint64_t bucket_id_{0};

        //! 64-bit fingerprints of keys in the current bucket accumulated before the recsplit is performed for that bucket
        std::vector<uint64_t> keys_;

        //! Index offsets for the current bucket
        std::vector<uint64_t> values_;

        //! Index offsets for the current bucket
        std::vector<uint64_t> offsets_;

        //! Helper to build GR codes of splitting and bijection indices, local to current bucket
        GolombRiceVector::LazyBuilder gr_builder_;

        //! The local max index used in Golomb parameter array
        uint16_t golomb_param_max_index_{0};

        //! Flag indicating if two-level index "recsplit -> enum" + "enum -> offset" is required
        bool double_enum_{false};

        //! Helper index output stream
        std::stringstream index_ofs{std::ios::in | std::ios::out | std::ios::binary};

        //! Mutex to protect concurrent access to the bucket
        std::mutex* mutex_;

        void clear() {
            // bucket_id_ = 0;
            keys_.clear();
            values_.clear();
            offsets_.clear();
            gr_builder_.clear();
            index_ofs.clear();
        }
    };

    void init(std::size_t bucket_size, std::size_t bucket_count, std::size_t key_count, bool double_enum_index) override {
        double_enum_index_ = double_enum_index;
        bucket_count_ = bucket_count;

        // Prepare buckets
        buckets_.reserve(bucket_count);
        for (int i = 0; i < bucket_count; i++)
            buckets_.emplace_back(i, bucket_size, double_enum_index_);
        if (double_enum_index_)
            offsets_.reserve(key_count);
    }

    void add_key(uint64_t bucket_id, uint64_t bucket_key, uint64_t offset, uint64_t ordinal) override {
        ensure(bucket_id < buckets_.size(), "bucket_id out of range");

        if (keys_added_ % 100'000 == 0) {
            SILK_TRACE << "[index] add key hash: bucket_id=" << bucket_id << " bucket_key=" << bucket_key << " offset=" << offset;
        }

        set_max(max_offset_, offset);

        Bucket& bucket = buckets_[bucket_id];

        bucket.add_key(bucket_key, offset, ordinal);

        keys_added_++;
    }

    bool build_mph_index(std::ofstream& index_output_stream, GolombRiceVector& golomb_rice_codes, uint16_t& golomb_param_max_index,
                         DoubleEliasFano& double_ef_index, uint8_t bytes_per_record) override {
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
        std::vector<int64_t> bucket_size_accumulator_(this->bucket_count_ + 1);      // accumulator for size of every bucket
        std::vector<int64_t> bucket_position_accumulator_(this->bucket_count_ + 1);  // accumulator for position of every bucket in the encoding of the hash function

        bucket_size_accumulator_[0] = bucket_position_accumulator_[0] = 0;
        for (size_t i = 0; i < this->bucket_count_; i++) {
            bucket_size_accumulator_[i + 1] = bucket_size_accumulator_[i] + buckets_[i].keys_.size();

            // auto* underlying_buffer = buckets_[i].index_ofs.rdbuf();
            // if (!is_empty(underlying_buffer))
            //     index_output_stream << underlying_buffer;
            char byte{0};
            while (buckets_[i].index_ofs.get(byte)) {  // maybe it is better to avoid this and use a buffer in place of index_ofs
                index_output_stream.put(byte);
            }
            // index_output_stream << buckets_[i].index_ofs.rdbuf();  // better but fails when rdbuf() is empty

            if (buckets_[i].keys_.size() > 1) {
                buckets_[i].gr_builder_.append_to(gr_builder_);
            }

            bucket_position_accumulator_[i + 1] = gr_builder_.get_bits();

            SILKWORM_ASSERT(bucket_size_accumulator_[i + 1] >= bucket_size_accumulator_[i]);
            SILKWORM_ASSERT(bucket_position_accumulator_[i + 1] >= bucket_position_accumulator_[i]);

            golomb_param_max_index = std::max(golomb_param_max_index, buckets_[i].golomb_param_max_index_);
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
        // Merge all offsets
        std::vector<std::vector<uint64_t>> all_vectors;
        for (size_t i = 0; i < bucket_count_; i++) {
            all_vectors.push_back(std::move(buckets_[i].offsets_));
        }
        offsets_ = merge_sorted_vectors(all_vectors);
        // Build Elias-Fano index for offsets
        ef_offsets = std::make_unique<EliasFano>(keys_added_, max_offset_);
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

            // it is unnecessary to sort keys and values

            std::vector<uint64_t> buffer_keys;     // temporary buffer for keys
            std::vector<uint64_t> buffer_offsets;  // temporary buffer for offsets
            buffer_keys.resize(bucket.keys_.size());
            buffer_offsets.resize(bucket.values_.size());

            RecSplit<LEAF_SIZE>::recsplit(
                bucket.keys_, bucket.values_, buffer_keys, buffer_offsets, bucket.gr_builder_,
                bucket.index_ofs, bucket.golomb_param_max_index_, bytes_per_record);
        } else {
            for (const auto offset : bucket.values_) {
                Bytes uint64_buffer(8, '\0');
                endian::store_big_u64(uint64_buffer.data(), offset);
                bucket.index_ofs.write(reinterpret_cast<const char*>(uint64_buffer.data()), 8);
                SILK_TRACE << "[index] written offset: " << offset;
            }
        }

        std::sort(bucket.offsets_.begin(), bucket.offsets_.end());

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
        return max_offset_.load();
    }

    //! The thread pool used for parallel processing
    ThreadPool& thread_pool_;

    //! Flag indicating if two-level index "recsplit -> enum" + "enum -> offset" is required
    bool double_enum_index_{false};

    //! Maximum value of offset used to decide how many bytes to use for Elias-Fano encoding
    std::atomic<uint64_t> max_offset_{0};

    //! The number of keys currently added
    std::atomic<uint64_t> keys_added_{0};

    //! The number of buckets for this Recsplit algorithm instance
    std::size_t bucket_count_{0};

    //! The buckets of the RecSplit algorithm
    std::vector<Bucket> buckets_;

    //! The offset collector for Elias-Fano encoding of "enum -> offset" index
    std::vector<uint64_t> offsets_;

    //! Helper to build GR codes of splitting and bijection indices
    GolombRiceBuilder gr_builder_;
};

inline auto par_build_strategy(ThreadPool& tp) { return std::make_unique<RecSplit8::ParallelBuildingStrategy>(tp); }

/*
 Example usage:
    RecSplit8 recsplit{RecSplitSettings{}, par_build_strategy(thread_pool)};
    auto collision = recsplit.build();
*/

}  // namespace silkworm::succinct

#pragma GCC diagnostic pop
