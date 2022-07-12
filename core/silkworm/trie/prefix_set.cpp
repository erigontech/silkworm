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

void PrefixSet::insert(ByteView key, bool marker) { insert(Bytes(key), marker); }

void PrefixSet::insert(Bytes&& key, bool marker) {
    nibbled_keys_.emplace_back(key, marker);
    sorted_ = false;
}

bool PrefixSet::contains(ByteView prefix) {
    if (nibbled_keys_.empty()) {
        return false;
    }

    // Key uniqueness and sorting
    ensure_sorted();

    // We optimize for the case when contains() queries are issued with increasing prefixes,
    // e.g. contains("00"), contains("04"), contains("0b"), contains("0b05"), contains("0c"), contains("0f"), ...
    // instead of some random order.
    while (index_ > 0 && nibbled_keys_[index_].first > prefix) {
        --index_;
    }

    for (size_t max_index{nibbled_keys_.size() - 1};; ++index_) {
        const auto& [key, _]{nibbled_keys_[index_]};
        if (key.starts_with(prefix)) {
            return true;
        }
        if (key > prefix || index_ == max_index) {
            return false;
        }
    }
}

ByteView PrefixSet::find_contains(ByteView prefix) {
    if (!contains(prefix)) {
        return {};
    }
    return {nibbled_keys_[index_].first};
}

std::pair<bool, ByteView> PrefixSet::contains_and_next_marked(ByteView prefix) {
    if (!contains(prefix)) {
        return {false, {}};
    }
    for (size_t i{index_ + 1}, e{nibbled_keys_.size() - 1}; i <= e; ++i) {
        if (nibbled_keys_[i].second) {
            return {true, ByteView(nibbled_keys_[i].first)};
        }
    }
    return {true, {}};  // There is no newly created account after this prefix
}

void PrefixSet::ensure_sorted() {
    if (!sorted_) {
        std::sort(nibbled_keys_.begin(), nibbled_keys_.end());
        nibbled_keys_.erase(std::unique(nibbled_keys_.begin(), nibbled_keys_.end()), nibbled_keys_.end());
        sorted_ = true;
    }
}
}  // namespace silkworm::trie
