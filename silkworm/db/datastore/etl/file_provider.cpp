// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "file_provider.hpp"

#include <filesystem>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/infra/common/safe_strerror.hpp>

namespace silkworm::datastore::etl {

namespace fs = std::filesystem;

// https://abseil.io/tips/117
FileProvider::FileProvider(std::string file_name, size_t id) : id_{id}, file_name_{std::move(file_name)} {}

FileProvider::~FileProvider() { reset(); }

void FileProvider::flush(Buffer& buffer) {
    EntryHeader head{};

    // Check we have enough space to store all data
    auto entries{buffer.entries()};
    file_size_ = buffer.size();
    fs::path workdir(fs::path(file_name_).parent_path());
    if (fs::space(workdir).available < file_size_) {
        file_size_ = 0;
        throw EtlError("Insufficient disk space");
    }

    // Open file for output and flush data
    file_.open(file_name_, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
    if (!file_.is_open()) {
        reset();
        throw EtlError(safe_strerror(errno));
    }

    for (const auto& entry : entries) {
        head.lengths[0] = static_cast<uint32_t>(entry.key.size());
        head.lengths[1] = static_cast<uint32_t>(entry.value.size());
        if (!file_.write(byte_ptr_cast(head.bytes), 8) ||
            !file_.write(byte_ptr_cast(entry.key.data()), static_cast<std::streamsize>(entry.key.size())) ||
            !file_.write(byte_ptr_cast(entry.value.data()), static_cast<std::streamsize>(entry.value.size()))) {
            auto err{errno};
            reset();
            throw EtlError(safe_strerror(err));
        }
    }

    // Close file in output mode and reopen for input mode
    // This is actually not strictly needed but amends an odd behavior on Windows
    // which prevents correct display of file size if the handle
    // has not been closed
    file_.close();
    file_.open(file_name_, std::ios_base::in | std::ios_base::binary);
    if (!file_.is_open()) {
        auto err{errno};
        reset();
        throw EtlError(safe_strerror(err));
    }
}

std::optional<std::pair<Entry, size_t>> FileProvider::read_entry() {
    EntryHeader head{};

    if (!file_.is_open() || !file_size_) {
        throw EtlError("Invalid file handle");
    }

    if (!file_.read(byte_ptr_cast(head.bytes), 8)) {
        reset();
        return std::nullopt;
    }

    Entry entry{Bytes(head.lengths[0], '\0'), Bytes(head.lengths[1], '\0')};
    if (!file_.read(byte_ptr_cast(entry.key.data()), head.lengths[0]) ||
        !file_.read(byte_ptr_cast(entry.value.data()), head.lengths[1])) {
        auto err{errno};
        reset();
        throw EtlError(safe_strerror(err));
    }

    return std::make_pair(entry, id_);
}

void FileProvider::reset() {
    file_size_ = 0;
    if (file_.is_open()) {
        file_.close();
        fs::remove(file_name_.c_str());
    }
}

std::string FileProvider::get_file_name() const { return file_name_; }

size_t FileProvider::get_file_size() const { return file_size_; }

}  // namespace silkworm::datastore::etl
