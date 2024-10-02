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
#include <memory>
#include <span>

#include "bloom_filter.hpp"

namespace silkworm::snapshots::index {

class BloomFilter;

//! Key existence index based on a Bloom filter implementation
class ExistenceIndex {
  public:
    class Reader {
      public:
        explicit Reader(std::filesystem::path index_file_path);

        std::filesystem::path path() const { return index_file_path_; }

        //! Insert an already hashed item into the index
        //! \param hash the hash value to add
        void add_hash(uint64_t hash);

        //! Checks if index contains the give \p hash value
        //! \param hash the hash value to check for presence
        //! \return false means "definitely does not contain value", true means "probably contains value"
        bool contains_hash(uint64_t hash);

      private:
        //! The index file path
        std::filesystem::path index_file_path_;

        //! The Bloom filter
        std::unique_ptr<BloomFilter> filter_;
    };
};

}  // namespace silkworm::snapshots::index
