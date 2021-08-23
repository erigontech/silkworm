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

#include "directories.hpp"

#include <random>

#include <silkworm/common/util.hpp>

namespace silkworm {

static std::string random_string(size_t len) {
    static constexpr char kAlphaNum[]{
        "0123456789"
        "abcdefghijklmnopqrstuvwxyz"};

    // don't count the null terminator
    static constexpr size_t kNumberOfCharacters{sizeof(kAlphaNum) - 1};

    std::random_device rd;
    std::default_random_engine engine{rd()};

    // yield random numbers up to and including kNumberOfCharacters - 1
    std::uniform_int_distribution<size_t> uniform_dist{0, kNumberOfCharacters - 1};

    std::string s;
    s.reserve(len);

    for (size_t i{0}; i < len; ++i) {
        size_t random_number{uniform_dist(engine)};
        s += kAlphaNum[random_number];
    }

    return s;
}

Directory::Directory(const std::filesystem::path& directory_path, bool must_create) {
    if (directory_path.empty()) {
        path_ = std::filesystem::current_path();
    } else {
        path_ = directory_path;
    }
    if (must_create) {
        create();
    }
}

bool Directory::is_pristine() const {
    if (!exists()) {
        return false;
    }
    return std::filesystem::is_empty(path_);
}

const std::filesystem::path& Directory::path() const { return path_; }

void Directory::clear() const {
    if (!exists()) {
        return;
    }
    for (const auto& item : std::filesystem::directory_iterator(path_)) {
        std::filesystem::remove_all(item.path());
    }
}
bool Directory::exists() const { return (std::filesystem::exists(path_) && std::filesystem::is_directory(path_)); }

void Directory::create() {
    if (exists()) {
        return;
    }
    std::error_code ec;
    std::filesystem::create_directories(path_, ec);
    if (ec) {
        throw std::invalid_argument("Directory " + path_.string() + " does not exist and could not be created");
    }
}
size_t Directory::size() const {
    size_t ret{0};
    for (const auto& item : std::filesystem::recursive_directory_iterator(path_)) {
        if (std::filesystem::is_directory(item.path())) {
            continue;
        }
        ret += std::filesystem::file_size(item.path());
    }
    return ret;
}

DataDirectory DataDirectory::from_chaindata(const std::filesystem::path& chaindata_path) {
    if (std::filesystem::equivalent(chaindata_path, std::filesystem::current_path())) {
        throw std::invalid_argument("Chaindata can't be current path");
    }
    if (chaindata_path.empty() || !std::filesystem::exists(chaindata_path) ||
        !std::filesystem::is_directory(chaindata_path)) {
        throw std::invalid_argument("Bad or not existent chaindata directory");
    }
    /// Ensure we treat path as absolute
    auto chaindata_path_absolute{std::filesystem::absolute(chaindata_path)};

    /// Chaindata must be at least 2 levels deep
    /*
<datadir>
├───chaindata
├───etl-temp
└───nodes
    ├───eth65
    └───eth66
    */

    if (std::filesystem::equivalent(chaindata_path_absolute, chaindata_path_absolute.root_path())) {
        throw std::invalid_argument("Chaindata directory can't be root");
    }

    std::string delimiter{std::filesystem::path::preferred_separator};
    auto tokens{silkworm::split(chaindata_path.string(), delimiter)};
    if (tokens.empty() || !iequals(tokens.back(), "chaindata")) {
        throw std::invalid_argument("Not a valid Silkworm chaindata path");
    }

    std::string base_path_str{};
    for (size_t i = 0; i < tokens.size() - 1; i++) {
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
    base_dir_path /= "Silkworm";
#elif __APPLE__
    base_dir_path /= "Library";
    base_dir_path /= "Silkworm";
#else
    base_dir_path /= ".local";
    base_dir_path /= "share";
    base_dir_path /= "silkworm";
#endif

    if (base_dir_path.has_filename()) {
        base_dir_path += std::filesystem::path::preferred_separator;
    }
    return base_dir_path;
}

void DataDirectory::deploy() {
    Directory::create();
    chaindata_.create();
    etl_.create();
    etl_.clear();
    nodes_.create();
}

std::filesystem::path TemporaryDirectory::get_os_temporary_path() {
    return std::filesystem::temp_directory_path();
}

std::filesystem::path TemporaryDirectory::get_unique_temporary_path(const std::filesystem::path& base_path) {
    if (base_path.empty()) {
        throw std::invalid_argument("Temporary base path is empty");
    }

    const auto absolute_base_path{std::filesystem::absolute(base_path)};
    if (!std::filesystem::exists(absolute_base_path) || !std::filesystem::is_directory(absolute_base_path)) {
        throw std::invalid_argument("Path " + absolute_base_path.string() + " does not exist or is not a directory");
    }

    /// Build random paths appending random strings of fixed length to base path
    for (int i = 0; i < 1000; ++i) {
        auto new_absolute_base_path{absolute_base_path / random_string(10)};
        if (!std::filesystem::exists(new_absolute_base_path)) {
            return new_absolute_base_path;
        }
    }

    /// We were unable to find a valid unique non-existent path
    throw std::runtime_error("Unable to find a valid unique non-existent path");
}

std::filesystem::path TemporaryDirectory::get_unique_temporary_path() {
    const auto base_path = TemporaryDirectory::get_os_temporary_path();
    return TemporaryDirectory::get_unique_temporary_path(base_path);
}

}  // namespace silkworm
