/*
   Copyright 2022 The Silkworm Authors

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

#include <filesystem>
#include <fstream>
#include <ios>
#include <string>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/common/directories.hpp>

namespace silkworm::test_util {

//! Temporary file flushing data after any insertion
class TemporaryFile {
  public:
    explicit TemporaryFile() : path_{TemporaryDirectory::get_unique_temporary_path()}, stream_{path_, std::ios::binary} {}
    explicit TemporaryFile(const std::string& filename)
        : path_{TemporaryDirectory::get_os_temporary_path() / filename}, stream_{path_, std::ios::binary} {}
    explicit TemporaryFile(const std::filesystem::path& tmp_dir, const std::string& filename)
        : path_{tmp_dir / filename}, stream_{path_, std::ios::binary} {}
    ~TemporaryFile() { stream_.close(); }

    const std::filesystem::path& path() const noexcept { return path_; }

    void write(ByteView bv) {
        stream_.write(reinterpret_cast<const char*>(bv.data()), static_cast<std::streamsize>(bv.size()));
        stream_.flush();
    }

  private:
    std::filesystem::path path_;
    std::ofstream stream_;
};

}  // namespace silkworm::test_util
