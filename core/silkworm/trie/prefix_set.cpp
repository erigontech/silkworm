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

void PrefixSet::insert(ByteView key) {
    keys_.emplace_back(key);
    sorted_ = false;
}

bool PrefixSet::contains(ByteView prefix) {
    if (keys_.empty()) {
        return false;
    }

    if (!sorted_) {
        std::sort(keys_.begin(), keys_.end());
        keys_.erase(std::unique(keys_.begin(), keys_.end()), keys_.end());
        sorted_ = true;
    }

    // We optimize for the case when contains() inquires are made with increasing prefixes,
    // e.g. contains("00"), contains("04"), contains("0b"), contains("0b05"), contains("0c"), contains("0f"), ...
    // instead of some random order.
    assert(index_ < keys_.size());
    while (index_ > 0 && keys_[index_] > prefix) {
        --index_;
    }

    while (true) {
        if (has_prefix(keys_[index_], prefix)) {
            return true;
        }
        if (keys_[index_] > prefix) {
            return false;
        }
        if (index_ == keys_.size() - 1) {
            return false;
        }
        ++index_;
    }
}

}  // namespace silkworm::trie
