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

// Portions of the following code and inspiration are taken from Aeron [https://github.com/real-logic/aeron]

/*
 * Copyright 2014-2022 Real Logic Limited.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#ifdef _WIN32
#pragma warning(disable : 4668)
#pragma warning(disable : 4710)
#pragma warning(disable : 4820)
#pragma warning(disable : 5039)
#endif

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <istream>
#include <optional>
#include <span>
#include <streambuf>
#include <tuple>

#ifndef _WIN32
#include <fcntl.h>
#include <ftw.h>
#include <pwd.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/types.h>
#endif

namespace silkworm {

#ifdef _WIN32
typedef void* HANDLE;
using FileDescriptor = HANDLE;
#else
using FileDescriptor = int;
#endif

using MemoryMappedRegion = std::span<uint8_t>;

class MemoryMappedFile {
  public:
    explicit MemoryMappedFile(std::filesystem::path path, std::optional<MemoryMappedRegion> region = {}, bool read_only = true);
    ~MemoryMappedFile();

    // Not copyable
    MemoryMappedFile(const MemoryMappedFile&) = delete;
    MemoryMappedFile& operator=(const MemoryMappedFile&) = delete;

    // Only movable
    MemoryMappedFile(MemoryMappedFile&& source) noexcept = default;
    MemoryMappedFile& operator=(MemoryMappedFile&& other) noexcept = default;

    [[nodiscard]] std::filesystem::path path() const {
        return path_;
    }

    [[nodiscard]] MemoryMappedRegion region() const {
        return region_;
    }

    [[nodiscard]] size_t size() const {
        return region_.size();
    }

    [[nodiscard]] std::filesystem::file_time_type last_write_time() const {
        return std::filesystem::last_write_time(path_);
    }

    void advise_normal() const;
    void advise_random() const;
    void advise_sequential() const;

  private:
    void map_existing(bool read_only);

    void* mmap(FileDescriptor fd, size_t size, bool read_only);
    void unmap();

    //! The path to the file
    std::filesystem::path path_;

    //! The area mapped in memory
    MemoryMappedRegion region_;

    //! Flag indicating if memory-mapping is managed internally or not
    bool managed_;

#ifdef _WIN32
    void cleanup();

    HANDLE file_ = nullptr;
    HANDLE mapping_ = nullptr;
#else
    void advise(int advice) const;
#endif
};

struct MemoryMappedStreamBuf : std::streambuf {
    MemoryMappedStreamBuf(MemoryMappedRegion region) {
        auto p = reinterpret_cast<char*>(region.data());
        this->setg(p, p, p + region.size());
    }
};

struct MemoryMappedInputStream : virtual MemoryMappedStreamBuf, std::istream {
    MemoryMappedInputStream(MemoryMappedRegion region)
        : MemoryMappedStreamBuf(region), std::istream(static_cast<std::streambuf*>(this)) {}
};

}  // namespace silkworm
