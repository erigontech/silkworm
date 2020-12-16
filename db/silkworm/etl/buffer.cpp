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

#include <silkworm/etl/buffer.hpp>
#include <algorithm>
#include <iostream>

namespace silkworm::etl{
bool compareEntries(const etl_entry lhs, const etl_entry rhs) {
    return lhs.key.compare(rhs.key) > 0;
}

Buffer::Buffer(size_t _optimal_size) {
    optimal_size = _optimal_size;
    entries = std::vector<etl_entry>();
    size = 0;
}

void Buffer::put(ByteView key, ByteView value) {
    size += value.size() + key.size();
    entries.push_back({key, value});
}

void Buffer::sort() {
    std::sort(entries.begin(), entries.end(), compareEntries);
    std::reverse(entries.begin(), entries.end());
}

std::vector<etl_entry> Buffer::get_entries() {
    return entries;
}

int Buffer::length() {
    return entries.size();
}

void Buffer::reset() {
    entries.clear();
    entries.shrink_to_fit();
    size = 0;
}

bool Buffer::check_flush_size() {
    return size >= optimal_size;
}
}