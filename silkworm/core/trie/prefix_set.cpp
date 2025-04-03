// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "prefix_set.hpp"

#include <algorithm>
#include <utility>

namespace silkworm::trie {

void PrefixSet::insert(ByteView key, bool marker) { insert(Bytes(key), marker); }

void PrefixSet::insert(Bytes&& key, bool marker) {
    keys_.emplace_back(std::move(key), marker);
    sorted_ = false;
}

bool PrefixSet::contains(ByteView prefix) {
    if (keys_.empty()) {
        return false;
    }

    // Key uniqueness and sorting
    ensure_sorted();

    // We optimize for the case when contains() queries are issued with increasing prefixes,
    // e.g. contains("00"), contains("04"), contains("0b"), contains("0b05"), contains("0c"), contains("0f"), ...
    // instead of some random order.
    while (index_ > 0 && keys_[index_].first > prefix) {
        --index_;
    }

    for (size_t max_index{keys_.size() - 1};; ++index_) {
        const auto& [key, _]{keys_[index_]};
        if (key.starts_with(prefix)) {
            return true;
        }
        if (key > prefix || index_ == max_index) {
            return false;
        }
    }
}

std::pair<bool, ByteView> PrefixSet::contains_and_next_marked(ByteView prefix, size_t invariant_prefix_len) {
    bool is_contained{contains(prefix)};
    ByteView next_created{};

    invariant_prefix_len = std::min(invariant_prefix_len, prefix.size());

    // Lookup next marked created key
    for (size_t i{index_}, e{keys_.size()}; i < e; ++i) {
        auto& item{keys_[i]};

        // Check we're in the same invariant part of the prefix
        if (invariant_prefix_len && std::memcmp(&prefix[0], &item.first[0], invariant_prefix_len) != 0) {
            break;
        }

        if (item.second) {
            next_created = ByteView(item.first);
            break;
        }
    }

    return {is_contained, next_created};
}

void PrefixSet::ensure_sorted() {
    if (!sorted_) {
        std::ranges::sort(keys_);
        const auto [first, last] = std::ranges::unique(keys_);
        keys_.erase(first, last);
        sorted_ = true;
    }
}

}  // namespace silkworm::trie
