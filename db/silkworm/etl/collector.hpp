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

#pragma once
#ifndef SILKWORM_ETL_COLLECTOR_H_
#define SILKWORM_ETL_COLLECTOR_H_

#include <silkworm/db/chaindb.hpp>
#include <silkworm/etl/buffer.hpp>
#include <silkworm/etl/file_provider.hpp>
#include <silkworm/etl/util.hpp>

// ETL : Extract, Transform, Load
// https://en.wikipedia.org/wiki/Extract,_transform,_load

namespace silkworm::etl {

constexpr size_t kOptimalBufferSize = 256 * kMebi;
constexpr size_t kIdealBatchSize = 128 * kMebi;  // TODO: Commit after ideal size is reached and open new transaction

// Function pointer to process Transform on before Load data into tables
typedef std::vector<Entry> (*LoadFunc)(Entry);

// Collects data Extracted from db
class Collector {
  public:
    Collector(const char* work_path = nullptr, size_t optimal_size = kOptimalBufferSize)
        : work_path_{set_work_path(work_path)}, buffer_(Buffer(optimal_size)){};
    ~Collector();

    void flush_buffer();                                 // Write buffer to file
    void collect(Entry& entry);                          // Store key-value pair in memory or on disk
    void load(lmdb::Table* table, LoadFunc load_func,
              unsigned int flags = 0);  // Load collected entries in destination table applying a transformation

  private:
    std::string set_work_path(const char* provided_work_path);

    std::string work_path_;
    std::vector<std::unique_ptr<FileProvider>> file_providers_;
    Buffer buffer_;
};

// Default no transform function
std::vector<Entry> identity_load(Entry entry);

}  // namespace silkworm::etl
#endif  // !SILKWORM_ETL_COLLECTOR_H_
