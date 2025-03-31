// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/util.hpp>

#include "buffer.hpp"
#include "collector_settings.hpp"
#include "file_provider.hpp"
#include "util.hpp"

// ETL : Extract, Transform, Load
// https://en.wikipedia.org/wiki/Extract,_transform,_load

namespace silkworm::datastore::etl {

inline constexpr size_t kOptimalBufferSize = 256_Mebi;

// Function pointer to process data loading
using LoadFunc = std::function<void(const Entry&)>;

// Collects data Extracted from db
class Collector {
  public:
    // Not copyable nor movable
    Collector(const Collector&) = delete;
    Collector& operator=(const Collector&) = delete;

    explicit Collector(
        const CollectorSettings& settings)
        : work_path_managed_{false},
          work_path_{settings.work_path},
          buffer_{settings.buffer_size} {};
    explicit Collector(const std::filesystem::path& work_path, size_t buffer_size = kOptimalBufferSize)
        : work_path_managed_{false}, work_path_{set_work_path(work_path)}, buffer_{buffer_size} {}
    explicit Collector(size_t buffer_size = kOptimalBufferSize)
        : work_path_managed_{true}, work_path_{set_work_path(std::nullopt)}, buffer_{buffer_size} {}

    ~Collector();

    // Store key-value pair in memory or on disk
    void collect(Entry entry);

    // Store key & value in memory or on disk
    void collect(Bytes key, Bytes value);

    //! \brief Loads and optionally transforms collected entries into db
    //! \param [in] load_func : Pointer to function transforming collected entries
    void load(const LoadFunc& load_func);

    //! \brief Returns the number of actually collected items
    size_t size() const { return size_; }

    //! \brief Returns the number of actually collected bytes
    size_t bytes_size() const { return bytes_size_; }

    //! \brief Returns whether this instance is empty (i.e. no items)
    bool empty() const { return size_ == 0; }

    //! \brief Clears contents of collector and reset
    void clear() {
        file_providers_.clear();
        buffer_.clear();
        size_ = 0;
        bytes_size_ = 0;
    }

    //! \brief Returns the hex representation of current load key (for progress tracking)
    std::string get_load_key() const {
        std::scoped_lock lock{mutex_};
        return loading_key_;
    }

  private:
    static std::filesystem::path set_work_path(const std::optional<std::filesystem::path>& provided_work_path);

    void flush_buffer();  // Write buffer to file

    void set_loading_key(ByteView key) {
        std::scoped_lock lock{mutex_};
        loading_key_ = to_hex(key, true);
    }

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

    std::vector<std::unique_ptr<FileProvider>> file_providers_;  // Collection of file providers
    size_t size_{0};                                             // Count of total collected items
    size_t bytes_size_{0};                                       // Count of total collected bytes
    mutable std::mutex mutex_{};                                 // To sync loading_key_
    std::string loading_key_{};                                  // Actual load key (for log purposes)
};

}  // namespace silkworm::datastore::etl
