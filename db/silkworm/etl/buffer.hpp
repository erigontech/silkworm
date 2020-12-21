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

#ifndef SILKWORM_ETL_BUFFER_H
#define SILKWORM_ETL_BUFFER_H

#include <algorithm>
#include <silkworm/common/base.hpp>
#include <silkworm/db/util.hpp>
#include <vector>

namespace silkworm::etl {

// In ETL, a buffer must be used stores entries, sort them and write them to file
class Buffer {
  public:
    Buffer(size_t optimal_size) : optimal_size_(optimal_size){};

    void put(db::Entry& entry);    // Add a new entry to the buffer
    void clear();                  // Free buffer's contents
    bool overflows();              // Whether or not accounted size overflows optimal_size_ (i.e. time to flush)
    void sort();                   // Sort buffer in crescent order by key comparison
    size_t size() const noexcept;  // Actual size of accounted data
    std::vector<db::Entry>& get_entries();

  private:
    std::vector<db::Entry> entries_;
    size_t optimal_size_;
    size_t size_ = 0;
};
}  // namespace silkworm::etl
#endif
