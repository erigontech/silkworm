// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
#include <utility>

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
    MemoryMappedFile(MemoryMappedFile&& other) noexcept
        : path_{std::move(other.path_)},
          region_{std::exchange(other.region_, {})},
#ifdef _WIN32
          file_{std::exchange(other.file_, nullptr)},
          mapping_{std::exchange(other.mapping_, nullptr)},
#endif
          managed_{std::exchange(other.managed_, false)} {
    }

    MemoryMappedFile& operator=(MemoryMappedFile&& other) noexcept {
        path_ = std::move(other.path_);
        region_ = std::exchange(other.region_, {});
#ifdef _WIN32
        file_ = std::exchange(other.file_, nullptr);
        mapping_ = std::exchange(other.mapping_, nullptr);
#endif
        managed_ = std::exchange(other.managed_, false);
        return *this;
    }

    std::filesystem::path path() const {
        return path_;
    }

    MemoryMappedRegion region() const {
        return region_;
    }

    size_t size() const {
        return region_.size();
    }

    std::filesystem::file_time_type last_write_time() const {
        return std::filesystem::last_write_time(path_);
    }

    void advise_normal() const;
    void advise_random() const;
    void advise_sequential() const;

  private:
    void map_existing(bool read_only);
    void close();

    void* mmap(FileDescriptor fd, size_t size, bool read_only);
    void unmap();
    void advise(int advice) const;

    //! The path to the file
    std::filesystem::path path_;

    //! The area mapped in memory
    MemoryMappedRegion region_;

#ifdef _WIN32
    HANDLE file_ = nullptr;
    HANDLE mapping_ = nullptr;
#endif

    //! Flag indicating if memory-mapping is managed internally or not
    bool managed_;
};

struct MemoryMappedStreamBuf : std::streambuf {
    explicit MemoryMappedStreamBuf(MemoryMappedRegion region) {
        auto p = reinterpret_cast<char*>(region.data());
        this->setg(p, p, p + region.size());
    }
};

struct MemoryMappedInputStream : virtual MemoryMappedStreamBuf, std::istream {
    explicit MemoryMappedInputStream(MemoryMappedRegion region)
        : MemoryMappedStreamBuf(region), std::istream(static_cast<std::streambuf*>(this)) {}
};

}  // namespace silkworm
