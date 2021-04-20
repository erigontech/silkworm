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

#include "temp_dir.hpp"

#include <random>

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

namespace fs = std::filesystem;

namespace silkworm {

fs::path create_temporary_directory(size_t max_tries) {
    fs::path tdp{fs::temp_directory_path()};
    for (size_t i{0}; i < max_tries; ++i) {
        fs::path path{tdp / random_string(/*len=*/10)};
        if (fs::create_directory(path)) {
            return path;
        }
    }

    throw std::runtime_error("could not find non-existing directory");
}

TemporaryDirectory::TemporaryDirectory() { path_ = create_temporary_directory().string(); }

TemporaryDirectory::~TemporaryDirectory() { fs::remove_all(path_); }

}  // namespace silkworm
