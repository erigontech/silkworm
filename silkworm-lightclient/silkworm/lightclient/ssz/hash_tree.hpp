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

#pragma once

#include <cstdint>

#include <silkworm/common/base.hpp>
#include <silkworm/lightclient/ssz/hasher.hpp>
#include <silkworm/lightclient/util/hash32.hpp>

namespace silkworm::ssz {

class HashTree {
  public:
    explicit HashTree(const Bytes& chunk_stream, std::uint64_t limit = 0);
    explicit HashTree(const Hash32Sequence& chunks, std::uint64_t limit = 0);

    [[nodiscard]] const Hash32Sequence& hash_tree() const { return hash_tree_; }
    [[nodiscard]] Hash32 root() const { return hash_tree_.back(); }

  private:
    static const Hasher hasher_;
    Hash32Sequence hash_tree_;
};

}  // namespace silkworm::ssz
