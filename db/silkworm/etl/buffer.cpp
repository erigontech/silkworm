/*
   Copyright 2020-2021 The Silkworm Authors

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

#include <cassert>

namespace silkworm::etl {

void Buffer::put(const Entry& entry) {
    size_ += entry.size();

    assert(length_ <= buffer_.size());
    if (length_ == buffer_.size()) {
        buffer_.push_back(entry);
    } else {
        buffer_[length_] = entry;
    }

    ++length_;
}

void Buffer::sort() { std::sort(buffer_.data(), buffer_.data() + length_); }

size_t Buffer::size() const noexcept { return size_; }

gsl::span<const Entry> Buffer::entries() const noexcept { return {buffer_.data(), length_}; }

void Buffer::clear() noexcept {
    length_ = 0;
    size_ = 0;
}

bool Buffer::overflows() const noexcept { return size_ >= optimal_size_; }

}  // namespace silkworm::etl
