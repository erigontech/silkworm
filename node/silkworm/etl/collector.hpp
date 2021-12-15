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

#include <silkworm/db/mdbx.hpp>
#include <silkworm/etl/buffer.hpp>
#include <silkworm/etl/file_provider.hpp>
#include <silkworm/etl/util.hpp>

// ETL : Extract, Transform, Load
// https://en.wikipedia.org/wiki/Extract,_transform,_load

namespace silkworm::etl {

inline constexpr size_t kOptimalBufferSize = 256_Mebi;

// Function pointer to process Load on before Load data into tables
typedef void (*LoadFunc)(const Entry&, mdbx::cursor&, MDBX_put_flags_t);

// Collects data Extracted from db
class Collector {
  public:
    // Not copyable nor movable
    Collector(const Collector&) = delete;
    Collector& operator=(const Collector&) = delete;

    explicit Collector(const std::filesystem::path& work_path, size_t optimal_size = kOptimalBufferSize)
        : work_path_managed_{false}, work_path_{set_work_path(work_path)}, buffer_{optimal_size} {}
    explicit Collector(size_t optimal_size = kOptimalBufferSize)
        : work_path_managed_{true}, work_path_{set_work_path(std::nullopt)}, buffer_{optimal_size} {}

    ~Collector();

    void collect(const Entry& entry);  // Store key-value pair in memory or on disk
    void collect(Entry&& entry);       // Store key-value pair in memory or on disk

    //! \brief Loads and optionally transforms collected entries into db
    //! \param [in] target : an mdbx cursor opened on target table
    //! \param [in] load_func : Pointer to function transforming collected entries. If NULL no transform is executed
    //! \param [in] flags : Optional put flags for append or upsert (default)
    //! \param [in] log_every_percent : Emits a log line indicating progress every this percent increment in processed
    //! items
    void load(mdbx::cursor& target, LoadFunc load_func = nullptr,
              MDBX_put_flags_t flags = MDBX_put_flags_t::MDBX_UPSERT, uint32_t log_every_percent = 100u);

    //! \brief Returns the number of actually collected items
    [[nodiscard]] size_t size() const { return size_; }

    //! \brief Returns whether this instance is empty (i.e. no items)
    [[nodiscard]] bool empty() const { return size_ == 0; }

    //! \brief Clears contents of collector and reset
    void clear() {
        file_providers_.clear();
        size_ = 0;
    }

  private:
    std::filesystem::path set_work_path(const std::optional<std::filesystem::path>& provided_work_path);
    void flush_buffer();  // Write buffer to file

    bool work_path_managed_;
    std::filesystem::path work_path_;
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
