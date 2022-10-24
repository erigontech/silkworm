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

#include "memory_mapped_file.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <ftw.h>
#include <unistd.h>

#include <cstring>

#include <sys/mman.h>
#endif

#include <stdexcept>
#include <string>

#include <gsl/util>

namespace silkworm {

const std::size_t MemoryMappedFile::kPageSize{MemoryMappedFile::get_page_size()};

MemoryMappedFile::MemoryMappedFile(const std::filesystem::path& path, bool read_only)
    : MemoryMappedFile(path.string().c_str(), read_only) {}

MemoryMappedFile::MemoryMappedFile(const char* path, bool read_only) : path_(path) {
    map_existing(read_only);
}

MemoryMappedFile::~MemoryMappedFile() {
    unmap();

#ifdef _WIN32
    cleanup();
#endif
}

#ifdef _WIN32
std::size_t MemoryMappedFile::get_page_size() noexcept {
    SYSTEM_INFO system_info;
    ::GetSystemInfo(&system_info);

    return static_cast<std::size_t>(system_info.dwPageSize);
}

void MemoryMappedFile::map_existing(bool read_only) {
    DWORD desired_access = read_only ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE);
    DWORD shared_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    FileDescriptor fd = {};
    fd = ::CreateFile(
        path_,
        desired_access,
        shared_mode,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (INVALID_HANDLE_VALUE == fd) {
        throw std::runtime_error{"Failed to create existing file: " + std::string{path_} + " error: " + std::to_string(GetLastError())};
    }

    auto _ = gsl::finally([fd]() { if (INVALID_HANDLE_VALUE != fd) ::CloseHandle(fd); });

    LARGE_INTEGER file_size;
    if (!::GetFileSizeEx(fd, &file_size)) {
        throw std::runtime_error{"GetFileSizeEx failed for: " + std::string{path_} + " error: " + std::to_string(GetLastError())};
    }

    length_ = static_cast<std::size_t>(file_size.QuadPart);

    address_ = static_cast<uint8_t*>(mmap(fd, read_only));
    fd = INVALID_HANDLE_VALUE;
}

void MemoryMappedFile::advise_random() {
}

void MemoryMappedFile::advise_sequential() {
}

void* MemoryMappedFile::mmap(FileDescriptor fd, bool read_only) {
    DWORD protection = static_cast<DWORD>(read_only ? PAGE_READONLY : PAGE_READWRITE);
    mapping_ = ::CreateFileMapping(fd, nullptr, protection, 0, static_cast<DWORD>(length_), nullptr);
    if (nullptr == mapping_) {
        throw std::runtime_error{"CreateFileMapping failed for: " + std::string{path_} + " error: " + std::to_string(GetLastError())};
    }

    DWORD desired_access = static_cast<DWORD>(read_only ? FILE_MAP_READ : FILE_MAP_ALL_ACCESS);
    void* memory = (LPTSTR)::MapViewOfFile(mapping_, desired_access, 0, static_cast<DWORD>(0), length_);

    return static_cast<std::uint8_t*>(memory);
}

void MemoryMappedFile::unmap() {
    if (address_ != nullptr) {
        ::UnmapViewOfFile(address_);
    }
}

void MemoryMappedFile::cleanup() {
    if (mapping_) {
        ::CloseHandle(mapping_);
        mapping_ = nullptr;
    }

    if (file_) {
        ::CloseHandle(file_);
        file_ = nullptr;
    }
}
#else
std::size_t MemoryMappedFile::get_page_size() noexcept {
    return static_cast<std::size_t>(::getpagesize());
}

void MemoryMappedFile::map_existing(bool read_only) {
    FileDescriptor fd = ::open(path_, read_only ? O_RDONLY : O_RDWR);
    if (fd == -1) {
        throw std::runtime_error{"open failed for: " + std::string{path_} + " error: " + strerror(errno)};
    }
    auto _ = gsl::finally([fd]() { ::close(fd); });

    struct stat stat_buffer {};
    if (::fstat(fd, &stat_buffer) == -1) {
        throw std::runtime_error{"fstat failed for: " + std::string{path_} + " error: " + strerror(errno)};
    }
    length_ = static_cast<std::size_t>(stat_buffer.st_size);

    address_ = static_cast<uint8_t*>(mmap(fd, read_only));
}

void MemoryMappedFile::advise_random() {
    advise(MADV_RANDOM);
}

void MemoryMappedFile::advise_sequential() {
    advise(MADV_SEQUENTIAL);
}

void* MemoryMappedFile::mmap(FileDescriptor fd, bool read_only) {
    int flags = MAP_SHARED;

#ifdef __linux__
    flags = flags | MAP_POPULATE;
#endif

    const auto address = ::mmap(nullptr, length_, read_only ? PROT_READ : (PROT_READ | PROT_WRITE), flags, fd, 0);
    if (address == MAP_FAILED) {
        throw std::runtime_error{"mmap failed for: " + std::string{path_} + " error: " + strerror(errno)};
    }

    return address;
}

void MemoryMappedFile::unmap() {
    if (address_ != nullptr) {
        const int result = ::munmap(address_, length_);
        if (result == -1) {
            throw std::runtime_error{"munmap failed for: " + std::string{path_} + " error: " + strerror(errno)};
        }
    }
}

void MemoryMappedFile::advise(int advice) {
    const int result = ::madvise(address_, length_, advice);
    if (result == -1) {
        // Ignore not implemented in kernel error because it still works (from Erigon)
        if (errno != ENOSYS) {
            throw std::runtime_error{"madvise failed for: " + std::string{path_} + " error: " + strerror(errno)};
        }
    }
}
#endif  // _WIN32

}  // namespace silkworm
