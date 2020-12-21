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

#ifndef SILKWORM_ETL_COLLECTOR_H
#define SILKWORM_ETL_COLLECTOR_H

#include <silkworm/db/chaindb.hpp>
#include <silkworm/etl/buffer.hpp>
#include <silkworm/etl/file_provider.hpp>

namespace silkworm::etl {

constexpr size_t kOptimalBufferSize = 256 * kMebi;
constexpr size_t kIdealBatchSize = 128 * kMebi;  // TODO: Commit after ideal size is reached and open new transaction
// After collection further processing can be made to key-value pairs.
// Returned vector of entries will be inserted afterwards.
typedef std::vector<Entry> (*Load)(ByteView, ByteView);
// Collector collects entries that needs to be sorted and load them in the table in sorted order
class Collector {
  public:
    Collector(size_t optimal_size) : buffer_(Buffer(optimal_size)){};

    void flush_buffer();                         // Write buffer to file
    void collect(ByteView key, ByteView value);  // Store key-value pair in memory or on disk
    void load(lmdb::Table* table, Load load);    // Load collected entries in destination table

  private:
    std::vector<FileProvider> file_providers_;
    Buffer buffer_;
};
// Load function for no processing
std::vector<Entry> default_load(ByteView key, ByteView value);

}  // namespace silkworm::etl
#endif
