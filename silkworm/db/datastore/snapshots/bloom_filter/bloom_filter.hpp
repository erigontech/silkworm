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

#include <array>
#include <cstdint>
#include <filesystem>
#include <istream>
#include <optional>
#include <vector>

#include "bloom_filter_key_hasher.hpp"

namespace silkworm::snapshots::bloom_filter {

//! Bloom filter implementation (https://en.wikipedia.org/wiki/Bloom_filter)
//! \remark Serialized binary format compatible with: https://github.com/holiman/bloomfilter
class BloomFilter {
  public:
    explicit BloomFilter(
        std::filesystem::path path,
        std::optional<BloomFilterKeyHasher> data_key_hasher = std::nullopt);
    BloomFilter();
    BloomFilter(uint64_t max_key_count, double p);

    const std::filesystem::path& path() const { return path_; }
    uint64_t bits_count() const { return bits_count_; }
    uint64_t key_count() const { return keys_.size(); }

    //! Insert an already hashed item to the filter
    //! \param hash the value to add
    void add_hash(uint64_t hash);

    //! Checks if filter contains the give \p hash value
    //! \param hash the value to check for presence
    //! \return false means "definitely does not contain value", true means "maybe contains value"
    bool contains_hash(uint64_t hash) const;
    bool contains(ByteView data_key) const;

    friend std::istream& operator>>(std::istream& is, BloomFilter& filter);

    static uint64_t optimal_bits_count(uint64_t max_key_count, double p);

    //! The fixed number of keys
    static constexpr size_t kHardCodedK = 3;

  private:
    using KeyArray = std::array<uint64_t, kHardCodedK>;

    static void ensure_min_bits_count(uint64_t bits_count);
    static KeyArray new_random_keys();

    BloomFilter(uint64_t bits_count, KeyArray keys);

    //! The index file path
    std::filesystem::path path_;

    //! Data key hasher
    std::optional<BloomFilterKeyHasher> data_key_hasher_;

    //! The number of bits that the bitmap should be able to track
    uint64_t bits_count_;

    //! The keys used to produce the bitmap entries associated to given hashes
    KeyArray keys_;

    //! The bitmap tracking the inserted elements
    std::vector<uint64_t> bits_;

    //! The number of elements inserted into the filter
    uint64_t inserted_count_{0};
};

}  // namespace silkworm::snapshots::bloom_filter
