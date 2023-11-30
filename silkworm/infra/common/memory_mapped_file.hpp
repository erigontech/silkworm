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

struct MemoryMappedRegion {
    uint8_t* address{nullptr};
    std::size_t length{0};
};

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

    [[nodiscard]] uint8_t* address() const {
        return address_;
    }

    [[nodiscard]] std::size_t length() const {
        return length_;
    }

    [[nodiscard]] std::filesystem::file_time_type last_write_time() const {
        return std::filesystem::last_write_time(path_);
    }

    void advise_normal();
    void advise_random();
    void advise_sequential();

  private:
    void map_existing(bool read_only);

    void* mmap(FileDescriptor fd, bool read_only);
    void unmap();

    //! The path to the file
    std::filesystem::path path_;

    //! The address of the mapped area
    uint8_t* address_{nullptr};

    //! The file size
    std::size_t length_{0};

    //! Flag indicating if memory-mapping is managed internally or not
    bool managed_;

#ifdef _WIN32
    void cleanup();

    HANDLE file_ = nullptr;
    HANDLE mapping_ = nullptr;
#else
    void advise(int advice);
#endif
};

struct MemoryMappedStreamBuf : std::streambuf {
    MemoryMappedStreamBuf(char const* base, std::size_t size) {
        char* p{const_cast<char*>(base)};  // NOLINT(cppcoreguidelines-pro-type-const-cast)
        this->setg(p, p, p + size);
    }
};

struct MemoryMappedInputStream : virtual MemoryMappedStreamBuf, std::istream {
    MemoryMappedInputStream(char const* base, std::size_t size)
        : MemoryMappedStreamBuf(base, size), std::istream(static_cast<std::streambuf*>(this)) {}
    MemoryMappedInputStream(unsigned char const* base, std::size_t size)
        : MemoryMappedInputStream(reinterpret_cast<char const*>(base), size) {}
};

}  // namespace silkworm
