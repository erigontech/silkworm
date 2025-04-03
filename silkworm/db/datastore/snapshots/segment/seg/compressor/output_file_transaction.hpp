// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <memory>
#include <ostream>

namespace silkworm::snapshots::seg {

class OutputFileTransactionImpl;

/**
 * An output file that is either fully written or deleted.
 * It opens a temporary file for writing,
 * and on commit() it fsync-s and renames it to the final file name.
 * If no commit() happens, the temporary file is deleted as if nothing has happened.
 */
class OutputFileTransaction {
  public:
    OutputFileTransaction(
        const std::filesystem::path& path,
        size_t buffer_size);
    ~OutputFileTransaction();

    void commit();

    std::ostream& stream();

  private:
    std::unique_ptr<OutputFileTransactionImpl> p_impl_;
};

}  // namespace silkworm::snapshots::seg
