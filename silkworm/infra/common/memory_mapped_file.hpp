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

class MemoryMappedFile {
  public:
    static const std::size_t kPageSize;

    explicit MemoryMappedFile(const std::filesystem::path& path, bool read_only = true);
    explicit MemoryMappedFile(const char* path, bool read_only = true);
    ~MemoryMappedFile();

    [[nodiscard]] uint8_t* address() const {
        return address_;
    }

    [[nodiscard]] std::size_t length() const {
        return length_;
    }

    void advise_random();
    void advise_sequential();

  private:
    [[nodiscard]] static std::size_t get_page_size() noexcept;

    void map_existing(bool read_only);

    void* mmap(FileDescriptor fd, bool read_only);
    void unmap();

    //! The path to the file
    const char* path_;

    //! The address of the mapped area
    uint8_t* address_{nullptr};

    //! The file size
    std::size_t length_{0};

#ifdef _WIN32
    void cleanup();

    HANDLE file_ = nullptr;
    HANDLE mapping_ = nullptr;
#else
    void advise(int advice);
#endif
};

}  // namespace silkworm
