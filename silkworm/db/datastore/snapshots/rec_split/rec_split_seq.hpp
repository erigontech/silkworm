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

#include <silkworm/db/datastore/etl/collector.hpp>

#include "rec_split.hpp"

namespace silkworm::snapshots::rec_split {

//! The recsplit sequential building strategy
template <size_t LEAF_SIZE>
struct RecSplit<LEAF_SIZE>::SequentialBuildingStrategy : public BuildingStrategy {
    explicit SequentialBuildingStrategy(size_t etl_optimal_size) : etl_optimal_size_{etl_optimal_size} {}

  protected:
    void setup(const RecSplitSettings& settings, size_t bucket_count) override {
        offset_collector_ = std::make_unique<datastore::etl::Collector>(etl_optimal_size_);
        bucket_collector_ = std::make_unique<datastore::etl::Collector>(etl_optimal_size_);

        bucket_size_accumulator_.reserve(bucket_count + 1);
        bucket_position_accumulator_.reserve(bucket_count + 1);
        bucket_size_accumulator_.resize(1);      // Start with 0 as bucket accumulated size
        bucket_position_accumulator_.resize(1);  // Start with 0 as bucket accumulated position
        current_bucket_.reserve(settings.bucket_size);
        current_bucket_offsets_.reserve(settings.bucket_size);
        double_enum_index_ = settings.double_enum_index;
    }

    void add_key(uint64_t bucket_id, uint64_t bucket_key, uint64_t offset) override {
        if (keys_added_ % 100'000 == 0) {
            SILK_DEBUG << "[index] add key hash: bucket_id=" << bucket_id << " bucket_key=" << bucket_key << " offset=" << offset;
        }

        max_offset_ = std::max(max_offset_, offset);

        Bytes collector_key(16, '\0');
        endian::store_big_u64(collector_key.data(), bucket_id);
        endian::store_big_u64(collector_key.data() + sizeof(uint64_t), bucket_key);
        Bytes offset_key(8, '\0');
        endian::store_big_u64(offset_key.data(), offset);

        if (double_enum_index_) {
            offset_collector_->collect(offset_key, {});

            Bytes current_key_count(8, '\0');
            endian::store_big_u64(current_key_count.data(), keys_added_);
            bucket_collector_->collect(collector_key, current_key_count);
        } else {
            bucket_collector_->collect(collector_key, offset_key);
        }

        ++keys_added_;
    }

    bool build_mph_index(
        std::ofstream& index_output_stream,
        GolombRiceVector& golomb_rice_codes,
        uint16_t& golomb_param_max_index,
        DoubleEliasFano& double_ef_index,
        uint8_t bytes_per_record) override {
        current_bucket_id_ = std::numeric_limits<uint64_t>::max();  // To make sure 0 bucket is detected

        [[maybe_unused]] auto _ = gsl::finally([&]() { bucket_collector_->clear(); });

        // We use an exception for collision error condition because ETL currently does not support loading errors
        // TODO(canepat) refactor ETL to support errors in LoadFunc and propagate them to caller to get rid of CollisionError
        struct CollisionError : public std::runtime_error {
            explicit CollisionError(uint64_t bucket_id) : runtime_error("collision"), bucket_id(bucket_id) {}
            uint64_t bucket_id;
        };
        try {
            // Not passing any cursor is a valid use-case for ETL when DB modification is not expected
            bucket_collector_->load([&](const datastore::etl::Entry& entry) {
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

    void build_enum_index(std::unique_ptr<EliasFanoBuilder>& ef_offsets) override {
        // Build Elias-Fano index for offsets (if any)
        ef_offsets = std::make_unique<EliasFanoBuilder>(keys_added_, max_offset_);
        offset_collector_->load([&](const datastore::etl::Entry& entry) {
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
            for (size_t i{1}; i < current_bucket_.size(); ++i) {
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
    size_t etl_optimal_size_{datastore::etl::kOptimalBufferSize};

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
    std::unique_ptr<datastore::etl::Collector> offset_collector_{};

    //! The ETL collector sorting keys by bucket
    std::unique_ptr<datastore::etl::Collector> bucket_collector_{};

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
};

inline auto seq_build_strategy(size_t etl_buffer_size = datastore::etl::kOptimalBufferSize) {
    return std::make_unique<RecSplit8::SequentialBuildingStrategy>(etl_buffer_size);
}

/* Example usage:
    RecSplit8 recsplit{RecSplitSettings{}, seq_build_strategy(datastore::etl::kOptimalBufferSize)};
    auto collision = recsplit.build();
 */

}  // namespace silkworm::snapshots::rec_split

#pragma GCC diagnostic pop
