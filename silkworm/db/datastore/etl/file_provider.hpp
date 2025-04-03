// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <fstream>
#include <memory>
#include <optional>

#include "buffer.hpp"
#include "util.hpp"

namespace silkworm::datastore::etl {

/**
 * Provides an abstraction to flush data to disk
 * and re-read flushed data sequentially
 */
class FileProvider {
  public:
    FileProvider(std::string file_name, size_t id);
    ~FileProvider();

    void flush(Buffer& buffer);                            // Write buffer's contents to disk
    std::optional<std::pair<Entry, size_t>> read_entry();  // Read next data element from file starting from position 0
    void reset();                                          // Remove the file when eof is met

    std::string get_file_name() const;
    size_t get_file_size() const;

  private:
    size_t id_;
    std::fstream file_;      // Actual file stream
    std::string file_name_;  // Actual name of file
    size_t file_size_{0};    // Actual size of written data
};

}  // namespace silkworm::datastore::etl
