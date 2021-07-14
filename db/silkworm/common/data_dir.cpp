/*
   Copyright 2021 The Silkworm Authors

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

#include "data_dir.hpp"

namespace silkworm {

DataDirectory::DataDirectory(std::filesystem::path base_path, bool create)
    : base_path_{base_path},
      chaindata_path_{base_path / "erigon" / "chaindata"},
      nodes_path_{base_path / "nodes"},
      etl_temp_path_{base_path / "etl-temp"} {
    if (!create) {
        if (!std::filesystem::exists(base_path_) || !std::filesystem::is_directory(base_path_)) {
            throw std::invalid_argument("Bad or not existent directory");
        }
    } else {
        if (!std::filesystem::exists(base_path_)) {
            if (!std::filesystem::create_directory(base_path_.native())) {
                throw std::runtime_error("Can't create base directory");
            }
        }
    }
}

DataDirectory DataDirectory::from_chaindata(std::filesystem::path chaindata_path) {
    if (!std::filesystem::exists(chaindata_path) || !std::filesystem::is_directory(chaindata_path) ||
        !chaindata_path.has_parent_path()) {
        throw std::invalid_argument("Bad or not existent chaindata directory");
    }

}

void DataDirectory::create_tree() {
    if (!std::filesystem::exists(chaindata_path_) || !std::filesystem::is_directory(chaindata_path_)) {
        if (!std::filesystem::create_directories(chaindata_path_.native())) {
            throw std::runtime_error("Can't create chaindata directory");
        }
    }

    if (!std::filesystem::exists(nodes_path_) || !std::filesystem::is_directory(nodes_path_)) {
        if (!std::filesystem::create_directories(nodes_path_.native())) {
            throw std::runtime_error("Can't create nodes directory");
        }
    }

    if (!std::filesystem::exists(etl_temp_path_) || !std::filesystem::is_directory(etl_temp_path_)) {
        if (!std::filesystem::create_directories(etl_temp_path_.native())) {
            throw std::runtime_error("Can't create etl-temp directory");
        }
    }
}

void DataDirectory::clear_etl_temp() {
    if (std::filesystem::exists(etl_temp_path_) && std::filesystem::is_directory(etl_temp_path_) &&
        !std::filesystem::is_empty(etl_temp_path_)) {
        for (auto& item : std::filesystem::directory_iterator(etl_temp_path_)) {
            std::filesystem::remove_all(item.path());
        }
    }
}

}  // namespace silkworm
