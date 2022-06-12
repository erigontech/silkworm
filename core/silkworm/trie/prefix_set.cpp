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

#include <silkworm/common/util.hpp>

namespace silkworm::trie {

void PrefixSet::insert(ByteView key) { insert(Bytes(key)); }

void PrefixSet::insert(Bytes&& key) {
    nibbled_keys_.emplace_back(key);
    sorted_ = false;
}

bool PrefixSet::contains(ByteView prefix) {
    // Applies uniqueness and sorting
    ensure_sorted();

    // We optimize for the most common case when contains() inquires are made with increasing prefixes,
    // e.g. contains("00"), contains("04"), contains("0b"), contains("0b05"), contains("0c"), contains("0f"), ...
    // instead of some random order.

    if (nibbled_keys_.empty()) {
        return false;  // There are no keys starting with prefix
    } else if (prefix.empty()) {
        nibbled_keys_it_ = nibbled_keys_.begin();  // Any string starts with an empty string
        return true;
    }

    // Should inquired prefix be already contained in last found key
    // then return early
    if ((*nibbled_keys_it_).starts_with(prefix)) {
        return true;
    } else {
        // This should rarely or not happen: it means current query prefix is < than prev query prefix
        // We need to reposition backwards
        while (*nibbled_keys_it_ > prefix && nibbled_keys_it_ != nibbled_keys_.begin()) {
            --nibbled_keys_it_;
        }
    }

    // Search for a new item containing prefix i.e. GTE than prefix
    auto tmp_it{std::lower_bound(nibbled_keys_it_, nibbled_keys_.end(), prefix)};
    if (tmp_it == nibbled_keys_.end() || !(*tmp_it).starts_with(prefix)) {
        nibbled_keys_it_ = --nibbled_keys_.end();  // Position to very last key
        return false;
    }

    // Found a matching item. Mark the new starting point for next search (assuming next prefix > current prefix)
    std::swap(nibbled_keys_it_, tmp_it);
    return true;
}

void PrefixSet::ensure_sorted() {
    if (!sorted_) {
        std::sort(nibbled_keys_.begin(), nibbled_keys_.end());
        nibbled_keys_.erase(std::unique(nibbled_keys_.begin(), nibbled_keys_.end()), nibbled_keys_.end());
        nibbled_keys_it_ = nibbled_keys_.begin();
        sorted_ = true;
    }
}

}  // namespace silkworm::trie
