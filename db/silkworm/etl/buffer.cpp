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

namespace silkworm::etl{
bool compare_buffer_entries(const Entry& lhs, const Entry& rhs) {
    return lhs.key.compare(rhs.key) > 0;
}

bool compare_heap_entries(const Entry& lhs, const Entry& rhs) {
    return lhs.key.compare(rhs.key) < 0;
}

void Buffer::put(ByteView& key, ByteView& value) {
    size_ += value.size() + key.size();
    entries_.push_back({key, value});
}

void Buffer::sort() {
    std::sort(entries_.begin(), entries_.end(), compare_buffer_entries);
}

std::vector<Entry> &Buffer::get_entries() {
    return entries_;
}

void Buffer::reset() {
    entries_.clear();
    entries_.shrink_to_fit();
    size_ = 0;
}

bool Buffer::check_flush_size() {
    return size_ >= optimal_size_;
}
}