/*
   Copyright 2021 The Silkworm Authors

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

#include "prefix_set.hpp"

#include <algorithm>
#include <cassert>

#include <silkworm/common/util.hpp>

namespace silkworm::trie {

void PrefixSet::insert(ByteView key) { insert(Bytes(key)); }

void PrefixSet::insert(Bytes&& key) {
    nibbled_keys_.push_back(std::move(key));
    sorted_ = false;
}

bool PrefixSet::contains(ByteView prefix) {
    if (nibbled_keys_.empty()) {
        return false;
    }
    if (prefix.empty()) {
        return true;
    }

    ensure_sorted();
    const size_t max_index{nibbled_keys_.size() - 1};

    // We optimize for the most common case when contains() inquires are made with increasing prefixes,
    // e.g. contains("00"), contains("04"), contains("0b"), contains("0b05"), contains("0c"), contains("0f"), ...
    // instead of some random order.
    // A note on string-viewish lexicographic comparators:
    // 1) A comparison amongst max common prefix length is performed. _Traits::compare(_Left, _Right, (_STD
    // min)(_Left_size, _Right_size)); 2) If the above does not return equality the shorter element is the lower
    // Due to the above we must consider:
    // - all nibbled keys have same length as, in trie, are all "nibblified" hashes -> 32*2 == 64bytes
    // - all prefixes inquired for have always a shorter len than keys

    while (lte_index_ > 0 && nibbled_keys_[lte_index_] > prefix) {
        --lte_index_;
    }
    while (true) {
        if (has_prefix(nibbled_keys_[lte_index_], prefix)) {
            return true;
        }
        if (nibbled_keys_[lte_index_] > prefix) {
            return false;
        }
        if (lte_index_ == max_index) {
            return false;
        }
        ++lte_index_;
    }
}

void PrefixSet::ensure_sorted() {
    if (!sorted_) {
        std::sort(nibbled_keys_.begin(), nibbled_keys_.end());
        nibbled_keys_.erase(std::unique(nibbled_keys_.begin(), nibbled_keys_.end()), nibbled_keys_.end());
        lte_index_ = std::min(nibbled_keys_.size() - 1, lte_index_);
        sorted_ = true;
    }
}

}  // namespace silkworm::trie
