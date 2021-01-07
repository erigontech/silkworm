/*
   Copyright 2020 The Silkworm Authors

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

#include <boost/filesystem/operations.hpp>

namespace silkworm::etl {

namespace fs = boost::filesystem;

FileProvider::FileProvider(const std::string &working_path, size_t id) : id_{id} {
    fs::path path{fs::path(working_path) / fs::path("tmp-" + std::to_string(id))};
    filename_ = path.string();
    file_.open(filename_, std::ios_base::in | std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
    if (!file_.is_open()) throw etl_error(strerror(errno));
}

void FileProvider::flush(Buffer &buffer) {
    head_t head{};

    // Verify we have enough space to store all data
    auto &entries{buffer.get_entries()};
    size_t data_size{buffer.size() + entries.size() * sizeof(head_t)};
    fs::path workdir(fs::path(filename_).parent_path());
    if (fs::space(workdir).available < data_size) {
        throw etl_error("Insufficient disk space");
    }

    for (const auto &entry : entries) {
        head.lengths[0] = entry.key.size();
        head.lengths[1] = entry.value.size();
        file_.write((const char *)head.bytes, 8);
        file_.write((const char *)entry.key.data(), entry.key.size());
        file_.write((const char *)entry.value.data(), entry.value.size());
        if (file_.fail()) {
            throw etl_error(strerror(errno));
        }
    }
    file_.seekg(0);
}

std::optional<std::pair<Entry, int>> FileProvider::read_entry() {
    head_t head{};
    file_.read((char *)head.bytes, 8);
    if (file_.eof()) {
        return std::nullopt;
    }
    if (file_.fail()) {
        throw etl_error(strerror(errno));
    }

    Entry entry{Bytes(head.lengths[0], '\0'), Bytes(head.lengths[1], '\0')};
    file_.read((char *)entry.key.data(), head.lengths[0]);
    file_.read((char *)entry.value.data(), head.lengths[1]);
    if (file_.fail()) {
        throw etl_error(strerror(errno));
    }

    return std::make_pair(entry, id_);
}

void FileProvider::reset() {
    file_.close();
    fs::remove(filename_.c_str());
}

}  // namespace silkworm::etl
