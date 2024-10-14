/*
   Copyright 2022 The Silkworm Authors

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

#pragma once

#include <algorithm>
#include <vector>

#include <silkworm/core/common/bytes.hpp>

#include "util.hpp"

namespace silkworm::db::etl {

inline constexpr size_t kInitialBufferCapacity = 32768;

// In ETL, a buffer must be used stores entries, sort them and write them to file
class Buffer {
  public:
    // Not copyable nor movable
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    explicit Buffer(size_t optimal_size) : optimal_size_(optimal_size) { buffer_.reserve(kInitialBufferCapacity); }

    void put(Entry entry) {
        // Add a new entry to the buffer
        size_ += entry.size() + sizeof(EntryHeader);
        buffer_.push_back(std::move(entry));
    }

    void clear() noexcept {
        // Set the buffer to contain 0 entries
        buffer_.clear();
        size_ = 0;
    }

    [[nodiscard]] bool overflows() const noexcept {
        // Whether accounted size overflows optimal_size_ (i.e. time to flush)
        return size_ >= optimal_size_;
    }

    void sort() {
        // Sort buffer in increasing order by key comparison
        std::sort(buffer_.begin(), buffer_.end());
    }

    [[nodiscard]] size_t size() const noexcept {
        // Actual size of accounted data
        return size_;
    }

    [[nodiscard]] const std::vector<Entry>& entries() const noexcept { return buffer_; }

  private:
    size_t optimal_size_;
    size_t size_ = 0;

    std::vector<Entry> buffer_;  // buffer for holding entries
};

}  // namespace silkworm::db::etl
