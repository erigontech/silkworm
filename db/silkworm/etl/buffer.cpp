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

void Buffer::put(db::Entry& entry) {
    size_ += entry.size();
    entries_.push_back(std::move(entry));
}

void Buffer::sort() {
    std::sort(entries_.begin(), entries_.end(),
              [](const db::Entry& a, const db::Entry& b) { return a.key.compare(b.key) > 0; });
}

size_t Buffer::size() const noexcept { return size_; }

std::vector<db::Entry>& Buffer::get_entries() { return entries_; }

void Buffer::clear() {
    std::vector<db::Entry>().swap(entries_);
    size_ = 0;
}

bool Buffer::overflows() { return size_ >= optimal_size_; }
}  // namespace silkworm::etl
