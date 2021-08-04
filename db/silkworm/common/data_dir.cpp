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

#include <silkworm/common/util.hpp>

namespace silkworm {

DataDirectory::DataDirectory(const std::filesystem::path& base_path, bool create)
    : base_path_{base_path},
      chaindata_path_{base_path / "erigon" / "chaindata"},
      nodes_path_{base_path / "nodes"},
      etl_temp_path_{base_path / "etl-temp"} {
    if (base_path_.has_filename()) {
        base_path_ += std::filesystem::path::preferred_separator;
    }
    if (chaindata_path_.has_filename()) {
        chaindata_path_ += std::filesystem::path::preferred_separator;
    }
    if (nodes_path_.has_filename()) {
        nodes_path_ += std::filesystem::path::preferred_separator;
    }
    if (etl_temp_path_.has_filename()) {
        etl_temp_path_ += std::filesystem::path::preferred_separator;
    }

    if (!create) {
        if (std::filesystem::exists(base_path_) && std::filesystem::is_directory(base_path_)) {
            valid_ = true;
        }
    } else {
        std::filesystem::create_directories(base_path_);
        valid_ = std::filesystem::exists(base_path_);
    }
}

DataDirectory DataDirectory::from_chaindata(std::filesystem::path chaindata_path) {
    if (!std::filesystem::exists(chaindata_path) || !std::filesystem::is_directory(chaindata_path)) {
        throw std::invalid_argument("Bad or not existent chaindata directory");
    }
    if (chaindata_path.has_filename()) {
        chaindata_path += std::filesystem::path::preferred_separator;
    }

    // Chaindata must be at least 3 levels deep
    /*
<datadir>
├───crashreports
├───erigon
│   ├───chaindata <--
│   └───nodes
├───etl-temp
└───nodes
    ├───eth65
    └───eth66
    */

    std::string delimiter{std::filesystem::path::preferred_separator};
    auto tokens{silkworm::split(chaindata_path.string(), delimiter)};

    if (tokens.size() <= 2) {
        throw std::runtime_error("Invalid base path");
    }

    if (!iequals(tokens.at(tokens.size() - 1), "chaindata") || !iequals(tokens.at(tokens.size() - 2), "erigon")) {
        throw std::invalid_argument("Not a valid erigon chaindata path");
    }

    std::string base_path_str{};
    for (size_t i = 0; i < tokens.size() - 2; i++) {
        base_path_str += tokens.at(i) + delimiter;
    }

    return DataDirectory(base_path_str);
}

std::filesystem::path silkworm::DataDirectory::get_default_storage_path() {
    std::string base_dir_str{};
    const char* env{std::getenv("XDG_DATA_HOME")};
    if (env) {
        // Got storage path from docker
        base_dir_str.assign(env);
    } else {
#ifdef _WIN32
        std::string env_name{"APPDATA"};
#else
        std::string env_name{"HOME"};
#endif
        env = std::getenv(env_name.c_str());
        if (!env) {
            // We don't actually know where to store data
            // fallback to current directory
            base_dir_str.assign(std::filesystem::current_path().string());
        } else {
            base_dir_str.assign(env);
        }
    }

    std::filesystem::path base_dir_path{base_dir_str};
#ifdef _WIN32
    base_dir_path /= "Erigon";
#elif __APPLE__
    base_dir_path /= "Library";
    base_dir_path /= "Erigon";
#else
    base_dir_path /= ".local";
    base_dir_path /= "share";
    base_dir_path /= "erigon";
#endif

    if (base_dir_path.has_filename()) {
        base_dir_path += std::filesystem::path::preferred_separator;
    }
    return base_dir_path;
}

void DataDirectory::create_tree() {
    std::filesystem::create_directories(chaindata_path_);
    std::filesystem::create_directories(nodes_path_);
    std::filesystem::create_directories(etl_temp_path_);

    if (!std::filesystem::exists(chaindata_path_) || !std::filesystem::is_directory(chaindata_path_)) {
        throw std::runtime_error("Can't create chaindata directory");
    }

    if (!std::filesystem::exists(nodes_path_) || !std::filesystem::is_directory(nodes_path_)) {
        throw std::runtime_error("Can't create nodes directory");
    }

    if (!std::filesystem::exists(etl_temp_path_) || !std::filesystem::is_directory(etl_temp_path_)) {
        throw std::runtime_error("Can't create etl-temp directory");
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
