/*
   Copyright 2020 The Silkworm Authors

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

#include "buffer.hpp"

namespace silkworm::etl {

void Buffer::reset() {
    delete[] entries_;
}

void Buffer::put(Entry& entry) {
    size_ += entry.size();
    if (length_ == buffer_cap_) {
        auto tmp{new Entry[buffer_cap_ * 2]};
        for(size_t i = 0; i < length_; i++) {
            tmp[i] = entries_[i];
        }
        buffer_cap_ *= 2;
        delete[] entries_;
        entries_ = tmp;
    }
    entries_[length_] = entry;
    ++length_;
}

void Buffer::sort() {
    std::sort(entries_.begin(), entries_.end(),
              [](const Entry& a, const Entry& b) { 
                auto diff{a.key.compare(b.key)};
                if (diff == 0) {
                    return a.value.compare(b.value) < 0;
                }
                return diff < 0; 
                });
}

size_t Buffer::size() const noexcept { return size_; }

size_t Buffer::length() const noexcept { return length_; }

Entry * Buffer::get_entries() { return entries_; }

void Buffer::clear() {
    length_ = 0;
    size_ = 0;
}

bool Buffer::overflows() const noexcept { return size_ >= optimal_size_; }
}  // namespace silkworm::etl
