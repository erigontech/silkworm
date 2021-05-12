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

#ifndef SILKWORM_ETL_BUFFER_HPP_
#define SILKWORM_ETL_BUFFER_HPP_

#include <algorithm>
#include <vector>

#include <gsl/span>

#include <silkworm/common/base.hpp>
#include <silkworm/etl/util.hpp>

namespace silkworm::etl {

constexpr size_t kInitialBufferCapacity = 32768;

// In ETL, a buffer must be used stores entries, sort them and write them to file
class Buffer {
  public:
    // Not copyable nor movable
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    explicit Buffer(size_t optimal_size) : optimal_size_(optimal_size), buffer_(kInitialBufferCapacity) {}

    void put(const Entry& entry);     // Add a new entry to the buffer
    void clear() noexcept;            // Set the buffer to contain 0 entries
    bool overflows() const noexcept;  // Whether or not accounted size overflows optimal_size_ (i.e. time to flush)
    void sort();                      // Sort buffer in increasing order by key comparison
    size_t size() const noexcept;     // Actual size of accounted data
    gsl::span<const Entry> entries() const noexcept;

  private:
    size_t optimal_size_;
    size_t size_ = 0;

    size_t length_ = 0;          // number of entries
    std::vector<Entry> buffer_;  // buffer for holding entries
};

}  // namespace silkworm::etl

#endif  // !SILKWORM_ETL_BUFFER_HPP_
