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

#include <vector>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace silkworm::trie {

/**
 * A set of "nibbled" byte strings with the following property:
 *  If x ∈ S and x starts with y, then y ∈ S.
 *  Corresponds to RetainList in Erigon.
 */
class PrefixSet {
  public:
    //! \brief Constructs an empty set.
    PrefixSet() = default;

    // copyable
    PrefixSet(const PrefixSet& other) = default;
    PrefixSet& operator=(const PrefixSet& other) = default;

    void insert(ByteView key, bool marker = false);
    void insert(Bytes&& key, bool marker = false);

    //! \brief Returns whether or not provided prefix is contained in any of the owned keys
    //! \remarks Doesn't change the set logically, but is not marked const since it's not safe to call this method
    //! concurrently. \see Erigon's RetainList::Retain
    bool contains(ByteView prefix);

    //! \brief Returns the next key with marker==true in the list
    //! \see Erigon's RetainList::RetainWithMarker
    //! \param [in] prefix : the prefix to search for
    //! \param [in] invariant_prefix_len : when searching for next marked the scanned items must begin with this number
    //! of identical bytes
    std::pair<bool, ByteView> contains_and_next_marked(ByteView prefix, size_t invariant_prefix_len = 0);

    [[nodiscard]] size_t size() const { return keys_.size(); }
    [[nodiscard]] bool empty() const { return keys_.empty(); }

    void clear() noexcept {
        keys_.clear();
        index_ = 0;
        sorted_ = false;
    }

  private:
    void ensure_sorted();

    std::vector<std::pair<Bytes, bool>> keys_;  // Collection of nibbled keys with marker of newly created
    size_t index_{0};                           // Index of last compared key
    bool sorted_{false};                        // Whether nibbled_keys_ has been unique-ed and sorted
};

}  // namespace silkworm::trie
