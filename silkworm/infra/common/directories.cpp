// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "directories.hpp"

#include <string_view>

#include <absl/strings/str_split.h>

#include <silkworm/core/common/random_number.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkworm {

static std::string random_string(size_t len) {
    static constexpr std::string_view kAlphaNum{
        "0123456789"
        "abcdefghijklmnopqrstuvwxyz"};

    static constexpr size_t kNumberOfCharacters{kAlphaNum.length()};

    // yield random numbers up to and including kNumberOfCharacters - 1
    RandomNumber rnd{0, kNumberOfCharacters - 1};

    std::string s;
    s.reserve(len);

    for (size_t i{0}; i < len; ++i) {
        size_t random_number{rnd.generate_one()};
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

bool Directory::is_empty() const {
    return exists() && std::filesystem::is_empty(path_);
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
    //! Ensure we treat path as absolute
    auto chaindata_path_absolute{std::filesystem::absolute(chaindata_path)};

    //! Chaindata must be at least 2 levels deep
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
    std::vector<std::string> tokens{absl::StrSplit(chaindata_path.string(), delimiter)};
    if (tokens.empty() || !iequals(tokens.back(), "chaindata")) {
        throw std::invalid_argument("Not a valid Silkworm chaindata path");
    }

    std::string base_path_str{};
    for (size_t i = 0; i < tokens.size() - 1; ++i) {
        base_path_str += tokens.at(i) + delimiter;
    }

    return DataDirectory(base_path_str);
}

std::filesystem::path silkworm::DataDirectory::get_default_storage_path() {
    std::string base_dir_str{};
    // C++11 guarantees some thread safety for std::getenv
    const char* env{std::getenv("XDG_DATA_HOME")};  // NOLINT(concurrency-mt-unsafe)
    if (env) {
        // Got storage path from docker
        base_dir_str.assign(env);
    } else {
#ifdef _WIN32
        std::string env_name{"APPDATA"};
#else
        std::string env_name{"HOME"};
#endif
        env = std::getenv(env_name.c_str());  // NOLINT(concurrency-mt-unsafe)
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
    nodes_.create();
    snapshots_.create();
    temp_.create();
    temp_.clear();
}

std::filesystem::path TemporaryDirectory::get_os_temporary_path() { return std::filesystem::temp_directory_path(); }

std::filesystem::path TemporaryDirectory::get_unique_temporary_path(const std::filesystem::path& base_path) {
    if (base_path.empty()) {
        throw std::invalid_argument("Temporary base path is empty");
    }

    const auto absolute_base_path{std::filesystem::absolute(base_path)};
    if (!std::filesystem::exists(absolute_base_path) || !std::filesystem::is_directory(absolute_base_path)) {
        throw std::invalid_argument("Path " + absolute_base_path.string() + " does not exist or is not a directory");
    }

    //! Build random paths appending random strings of fixed length to base path
    for (int i = 0; i < 1000; ++i) {
        auto new_absolute_base_path{absolute_base_path / random_string(10)};
        if (!std::filesystem::exists(new_absolute_base_path)) {
            return new_absolute_base_path;
        }
    }

    //! We were unable to find a valid unique non-existent path
    throw std::runtime_error("Unable to find a valid unique non-existent path");
}

std::filesystem::path TemporaryDirectory::get_unique_temporary_path() {
    const auto base_path = TemporaryDirectory::get_os_temporary_path();
    return TemporaryDirectory::get_unique_temporary_path(base_path);
}

}  // namespace silkworm
