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

#include <vector>
#include <algorithm>
#include <vector>
#include <silkworm/common/base.hpp>
#ifndef SILKWORM_ETL_BUFFER_H
#define SILKWORM_ETL_BUFFER_H

namespace silkworm::etl{
// Key-Value pairs used in ETL
struct Entry {
    ByteView key;
    ByteView value;
    int i; // Used only for heap operations
};
// Compare entries by key comparison
bool compareEntries(const Entry lhs, const Entry rhs);

// In ETL, a buffer must be used stores entries, sort them and write them to file
class Buffer {
   public:
    Buffer(size_t optimal_size): optimal_size_(optimal_size) {};

    void put(ByteView key, ByteView value); // Add a new entry to the buffer
    void reset();                                               // Free the buffer after writting to file
    bool check_flush_size();                                    // Check if buffer reached optimal size
    void sort();                                                // Sort buffer in crescent order by key comparison
    std::vector<Entry> &get_entries();

   private:

    std::vector<Entry> entries_;
    size_t optimal_size_;
    size_t size_ = 0;
};
}
#endif