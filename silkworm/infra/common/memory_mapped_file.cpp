// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "memory_mapped_file.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>

#include <cstring>

#include <sys/mman.h>
#endif

#include <stdexcept>
#include <string>

#include <gsl/util>

#include "ensure.hpp"
#include "safe_strerror.hpp"

namespace silkworm {

MemoryMappedFile::MemoryMappedFile(std::filesystem::path path, std::optional<MemoryMappedRegion> region, bool read_only)
    : path_(std::move(path)), managed_{!region.has_value()} {
    ensure(std::filesystem::exists(path_), [&]() { return "MemoryMappedFile: " + path_.string() + " does not exist"; });
    ensure(std::filesystem::is_regular_file(path_), [&]() { return "MemoryMappedFile: " + path_.string() + " is not regular file"; });

    if (region) {
        ensure(region->data() != nullptr, "MemoryMappedFile: address is null");
        ensure(!region->empty(), "MemoryMappedFile: length is zero");
        region_ = *region;
    } else {
        map_existing(read_only);
    }
}

MemoryMappedFile::~MemoryMappedFile() {
    close();
}

#ifdef _WIN32

void MemoryMappedFile::map_existing(bool read_only) {
    DWORD desired_access = read_only ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE);
    DWORD shared_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    FileDescriptor fd = {};
    fd = ::CreateFile(
        path_.string().c_str(),
        desired_access,
        shared_mode,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (INVALID_HANDLE_VALUE == fd) {
        throw std::runtime_error{"Failed to create existing file: " + path_.string() + " error: " + std::to_string(GetLastError())};
    }

    [[maybe_unused]] auto _ = gsl::finally([fd]() { if (INVALID_HANDLE_VALUE != fd) ::CloseHandle(fd); });

    auto size = std::filesystem::file_size(path_);
    auto address = static_cast<uint8_t*>(mmap(fd, size, read_only));
    region_ = {address, size};

    fd = INVALID_HANDLE_VALUE;
}

void MemoryMappedFile::advise_normal() const {
}

void MemoryMappedFile::advise_random() const {
}

void MemoryMappedFile::advise_sequential() const {
}

void MemoryMappedFile::advise(int /*advice*/) const {
}

void* MemoryMappedFile::mmap(FileDescriptor fd, size_t size, bool read_only) {
    DWORD protection = static_cast<DWORD>(read_only ? PAGE_READONLY : PAGE_READWRITE);

    mapping_ = ::CreateFileMapping(fd, nullptr, protection, 0, 0, nullptr);  // note: no size specified to avoid MapViewOfFile failure
    if (nullptr == mapping_) {
        throw std::runtime_error{"CreateFileMapping failed for: " + path_.string() + " error: " + std::to_string(GetLastError())};
    }

    DWORD desired_access = static_cast<DWORD>(read_only ? FILE_MAP_READ : FILE_MAP_ALL_ACCESS);
    void* memory = (LPTSTR)::MapViewOfFile(mapping_, desired_access, 0, static_cast<DWORD>(0), size);

    if (memory == nullptr) {
        throw std::runtime_error{"MapViewOfFile failed for: " + path_.string() + " error: " + std::to_string(GetLastError())};
    }

    return static_cast<std::uint8_t*>(memory);
}

void MemoryMappedFile::unmap() {
    if (region_.data() != nullptr) {
        ::UnmapViewOfFile(region_.data());
    }
}

void MemoryMappedFile::close() {
    if (!managed_) return;

    if (region_.data()) {
        unmap();
        region_ = {};
        managed_ = false;
    }

    if (mapping_) {
        ::CloseHandle(mapping_);
        mapping_ = nullptr;
    }

    if (file_) {
        ::CloseHandle(file_);
        file_ = nullptr;
    }
}

#else  // !_WIN32

void MemoryMappedFile::map_existing(bool read_only) {
    FileDescriptor fd = ::open(path_.c_str(), read_only ? O_RDONLY : O_RDWR);
    if (fd == -1) {
        throw std::runtime_error{"open failed for: " + path_.string() + " error: " + safe_strerror(errno)};
    }
    [[maybe_unused]] auto _ = gsl::finally([fd]() { ::close(fd); });

    auto size = std::filesystem::file_size(path_);
    auto address = static_cast<uint8_t*>(mmap(fd, size, read_only));
    region_ = {address, size};
}

void MemoryMappedFile::close() {
    if (!managed_) return;

    if (region_.data()) {
        unmap();
        region_ = {};
        managed_ = false;
    }
}

void MemoryMappedFile::advise_normal() const {
    advise(MADV_NORMAL);
}

void MemoryMappedFile::advise_random() const {
    advise(MADV_RANDOM);
}

void MemoryMappedFile::advise_sequential() const {
    advise(MADV_SEQUENTIAL);
}

void* MemoryMappedFile::mmap(FileDescriptor fd, size_t size, bool read_only) {
    int flags = MAP_SHARED;

    const auto address = ::mmap(nullptr, size, read_only ? PROT_READ : (PROT_READ | PROT_WRITE), flags, fd, 0);
    if (address == MAP_FAILED) {
        throw std::runtime_error{"mmap failed for: " + path_.string() + " error: " + safe_strerror(errno)};
    }

    return address;
}

void MemoryMappedFile::unmap() {
    if (region_.data() != nullptr) {
        const int result = ::munmap(region_.data(), region_.size());
        if (result == -1) {
            throw std::runtime_error{"munmap failed for: " + path_.string() + " error: " + safe_strerror(errno)};
        }
    }
}

void MemoryMappedFile::advise(int advice) const {
    const int result = ::madvise(region_.data(), region_.size(), advice);
    if (result == -1) {
        // Ignore not implemented in kernel error because it still works (from Erigon)
        if (errno != ENOSYS) {
            throw std::runtime_error{"madvise failed for: " + path_.string() + " error: " + safe_strerror(errno)};
        }
    }
}

#endif  // _WIN32

}  // namespace silkworm
