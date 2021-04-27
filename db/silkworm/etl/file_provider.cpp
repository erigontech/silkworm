/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "file_provider.hpp"

#include <filesystem>

#include <silkworm/common/cast.hpp>

namespace silkworm::etl {

namespace fs = std::filesystem;

// https://abseil.io/tips/117
FileProvider::FileProvider(std::string file_name, size_t id) : id_{id}, file_name_{std::move(file_name)} {}

FileProvider::~FileProvider(void) { reset(); }

void FileProvider::flush(Buffer &buffer) {
    head_t head{};

    // Check we have enough space to store all data
    auto entries{buffer.entries()};
    file_size_ = {buffer.size() + entries.size() * sizeof(head_t)};
    fs::path workdir(fs::path(file_name_).parent_path());
    if (fs::space(workdir).available < file_size_) {
        file_size_ = 0;
        throw etl_error("Insufficient disk space");
    }

    // Open file for output and flush data
    file_.open(file_name_, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
    if (!file_.is_open()) {
        reset();
        throw etl_error(strerror(errno));
    };

    for (const auto &entry : entries) {
        head.lengths[0] = entry.key.size();
        head.lengths[1] = entry.value.size();
        if (!file_.write(byte_ptr_cast(head.bytes), 8) ||
            !file_.write(byte_ptr_cast(entry.key.data()), entry.key.size()) ||
            !file_.write(byte_ptr_cast(entry.value.data()), entry.value.size())) {
            auto err{errno};
            reset();
            throw etl_error(strerror(err));
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
        throw etl_error(strerror(err));
    };
}

std::optional<std::pair<Entry, int>> FileProvider::read_entry() {
    head_t head{};

    if (!file_.is_open() || !file_size_) {
        throw etl_error("Invalid file handle");
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
        throw etl_error(strerror(err));
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

std::string FileProvider::get_file_name(void) const { return file_name_; }

size_t FileProvider::get_file_size(void) const { return file_size_; }

}  // namespace silkworm::etl
