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

#ifndef SILKWORM_ETL_COLLECTOR_HPP_
#define SILKWORM_ETL_COLLECTOR_HPP_

#include <silkworm/etl/buffer.hpp>
#include <silkworm/db/mdbx.hpp>
#include <silkworm/etl/file_provider.hpp>
#include <silkworm/etl/util.hpp>

// ETL : Extract, Transform, Load
// https://en.wikipedia.org/wiki/Extract,_transform,_load

namespace silkworm::etl {

constexpr size_t kOptimalBufferSize = 256 * kMebi;

// Function pointer to process Load on before Load data into tables
typedef void (*LoadFunc)(Entry, mdbx::cursor&, MDBX_put_flags_t);

// Collects data Extracted from db
class Collector {
  public:
    // Not copyable nor movable
    Collector(const Collector&) = delete;
    Collector& operator=(const Collector&) = delete;

    explicit Collector(const char* work_path = nullptr, size_t optimal_size = kOptimalBufferSize)
        : work_path_{set_work_path(work_path)}, buffer_{optimal_size} {}

    ~Collector();

    void collect(const Entry& entry);  // Store key-value pair in memory or on disk

    /** @brief Loads and optionally transforms collected entries into db
     *
     * @param table : The target db table
     * @param load_func : Pointer to function transforming collected entries. If NULL no transform is executed
     * @param flags : Optional whether to append or upsert (default)
     * @param log_every_percent : Emits a log line indicating progress every this percent increment in processed items
     */
    void load(mdbx::cursor& target, LoadFunc load_func = nullptr, MDBX_put_flags_t flags = MDBX_put_flags_t::MDBX_UPSERT,
              uint32_t log_every_percent = 100u);

    /** @brief Returns the number of actually collected items
     */
    size_t size() const;

  private:
    std::string set_work_path(const char* provided_work_path);
    void flush_buffer();  // Write buffer to file

    std::string work_path_;
    Buffer buffer_;

    /*
     * TL;DR; In no way two instances of collector can have
     * the same unique_id_
     *
     * This id will be unique across the application
     * No other object will be located at the same address
     * If this object gets destroyed another object may get
     * the same address but in such case all dependant files
     * would be already destroyed too thus keeping file
     * names uniqueness.
     */
    uintptr_t unique_id_{reinterpret_cast<uintptr_t>(this)};

    std::vector<std::unique_ptr<FileProvider>> file_providers_;
    size_t size_{0};
};

}  // namespace silkworm::etl

#endif  // SILKWORM_ETL_COLLECTOR_HPP_
