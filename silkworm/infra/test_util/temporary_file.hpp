// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <fstream>
#include <ios>
#include <string>
#include <variant>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/common/directories.hpp>

namespace silkworm::test_util {

//! Temporary file flushing data after any insertion
class TemporaryFile {
  public:
    TemporaryFile()
        : TemporaryFile{TemporaryDirectory::get_unique_temporary_path(), std::monostate{}} {}
    explicit TemporaryFile(const std::string& filename)
        : TemporaryFile{TemporaryDirectory::get_os_temporary_path() / filename, std::monostate{}} {}
    TemporaryFile(const std::filesystem::path& tmp_dir, const std::string& filename)
        : TemporaryFile{tmp_dir / filename, std::monostate{}} {}
    ~TemporaryFile() { stream_.close(); }

    const std::filesystem::path& path() const noexcept { return path_; }

    void write(ByteView bv) {
        stream_.write(reinterpret_cast<const char*>(bv.data()), static_cast<std::streamsize>(bv.size()));
        stream_.flush();
    }

  private:
    TemporaryFile(std::filesystem::path path, std::monostate /*sentinel*/)
        : path_{std::move(path)},
          stream_{path_, std::ios::binary} {
        stream_.exceptions(std::ios::failbit | std::ios::badbit);
    }

    std::filesystem::path path_;
    std::ofstream stream_;
};

}  // namespace silkworm::test_util
