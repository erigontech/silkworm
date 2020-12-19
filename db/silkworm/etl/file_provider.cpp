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
#include <iostream>
#include <silkworm/etl/error.hpp>

namespace silkworm::etl{

FileProvider::FileProvider(int id) {
    filename_ = "tmp" + std::to_string(id);
    file_.open(filename_, std::ios_base::in | std::ios_base::out | std::ios_base::trunc);
    if (!file_.is_open()) throw ETLError(strerror(errno));
}

void FileProvider::write_buffer_to_disk(std::vector<Entry>& entries) {
    head_t head{};
    for(const auto& entry: entries) {
        head.lengths[0] = entry.key.size();
        head.lengths[1] = entry.value.size();
        file_.write((const char *) head.bytes, 8);
        file_.write((const char *) entry.key.data(), entry.key.size());
        file_.write((const char *) entry.value.data(), entry.value.size());
        if (file_.fail()) {
            throw ETLError(strerror(errno));
        }
    }
    file_.seekg(0);
}

Entry FileProvider::read_entry() {
    head_t head{};
    file_.read((char *)head.bytes, 8);
    if (file_.eof()) {
        return {ByteView(), ByteView()};
    }
    if (file_.fail()) {
        throw ETLError(strerror(errno));
    }
    auto key{new unsigned char[head.lengths[0]]};
    auto value{new unsigned char[head.lengths[1]]};
    file_.read((char *)key, head.lengths[0]);
    file_.read((char *)value, head.lengths[1]);
    if (file_.fail()) {
        throw ETLError(strerror(errno));
    }
    return {ByteView(key, head.lengths[0]), ByteView(value, head.lengths[1])};
}

void FileProvider::reset() {
    file_.close();
    boost::filesystem::remove(filename_.c_str());
}

}