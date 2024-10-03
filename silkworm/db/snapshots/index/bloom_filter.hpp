/*
   Copyright 2024 The Silkworm Authors

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

#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/common/memory_mapped_file.hpp>

namespace silkworm::snapshots::index {

//! Bloom filter implementation (https://en.wikipedia.org/wiki/Bloom_filter)
//! \remark Serialized binary format compatible with: https://github.com/holiman/bloomfilter
class BloomFilter {
  public:
    //! The minimum Bloom filter bits count
    static constexpr size_t kMinimumBitsCount = 2;

    //! The fixed number of keys
    static constexpr size_t kHardCodedK = 3;

    using KeyArray = std::array<uint64_t, kHardCodedK>;

    static uint64_t optimal_bits_count(uint64_t max_key_count, double p);

    explicit BloomFilter(uint64_t bits_count = kMinimumBitsCount);
    BloomFilter(uint64_t max_key_count, double p);

    uint64_t bits_count() const { return bits_count_; }
    uint64_t key_count() const { return keys_.size(); }

    //! Insert an already hashed item to the filter
    //! \param hash the value to add
    void add_hash(uint64_t hash);

    //! Checks if filter contains the give \p hash value
    //! \param hash the value to check for presence
    //! \return false means "definitely does not contain value", true means "maybe contains value"
    bool contains_hash(uint64_t hash);

    friend std::istream& operator>>(std::istream& is, BloomFilter& filter);

  private:
    static void ensure_min_bits_count(uint64_t bits_count);
    static KeyArray new_random_keys();

    BloomFilter(uint64_t bits_count, KeyArray keys);

    //! The number of bits that the bitmap should be able to track
    uint64_t bits_count_;

    //! The keys used to produce the bitmap entries associated to given hashes
    KeyArray keys_;

    //! The bitmap tracking the inserted elements
    std::vector<uint64_t> bits_;

    //! The number of elements inserted into the filter
    uint64_t inserted_count_{0};
};

}  // namespace silkworm::snapshots::index
