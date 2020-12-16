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

#include <silkworm/etl/fileProvider.hpp>
<<<<<<< HEAD
=======
#include <boost/endian/conversion.hpp>
#include <silkworm/common/util.hpp>
#include <string.h>
#include <cstdio>
#include <stdlib.h>
#include <sys/stat.h>
#include <iostream>
>>>>>>> added comments

namespace silkworm::etl{

FileProvider::FileProvider(Buffer * buffer, int id) {
<<<<<<< HEAD
    filename_ = "tmp" + std::to_string(id);
    file_.open(filename_, std::ios_base::in | std::ios_base::out | std::ios_base::trunc);
=======
    filename = "tmp" + std::to_string(id);
    file.open(filename, std::ios_base::in | std::ios_base::out | std::ios_base::trunc);
>>>>>>> added comments
    auto entries{buffer->get_entries()};
    for(auto entry: entries) {
        auto writes{std::string()};
        unsigned char length_key[4];
        unsigned char length_value[4];
        boost::endian::store_big_u32(length_key, entry.key.size());
        boost::endian::store_big_u32(length_value, entry.value.size());
        writes.append(std::string((const char *) length_key, 4));
        writes.append(std::string((const char *) length_value, 4));
        writes.append(std::string((const char *) entry.key.data(), entry.key.size()));
        writes.append(std::string((const char *) entry.value.data(), entry.value.size()));
<<<<<<< HEAD
        file_ << writes;
    }
    file_.seekp(0);
}

Entry FileProvider::next() {
    char buffer_key_length[4];
    char buffer_value_length[4];

    file_.read(buffer_key_length, 4);
    file_.read(buffer_value_length, 4);

    if (file_.eof()) {
=======
        file << writes;
    }
    file.seekp(0);
}

etl_entry FileProvider::next() {
    char buffer_key_length[4];
    char buffer_value_length[4];

    file.read(buffer_key_length, 4);
    file.read(buffer_value_length, 4);

    if (file.eof()) {
>>>>>>> added comments
        return {ByteView(), ByteView()};
    }

    auto key_length = boost::endian::load_big_u32((unsigned char *)buffer_key_length);
    auto value_length = boost::endian::load_big_u32((unsigned char *)buffer_value_length);
    auto key{new unsigned char[key_length]};
    auto value{new unsigned char[value_length]};
<<<<<<< HEAD
    file_.read((char *)key, key_length);
    file_.read((char *)value, value_length);
=======

    file.read((char *)key, key_length);
    file.read((char *)value, value_length);

>>>>>>> added comments
    return {ByteView(key, key_length), ByteView(value, value_length)};
}

void FileProvider::reset() {
<<<<<<< HEAD
    std::remove(filename_.c_str());
=======
    std::remove(filename.c_str());
>>>>>>> added comments
}

}