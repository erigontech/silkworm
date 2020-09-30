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

#include "temp_dir.hpp"

#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

namespace silkworm {

TemporaryDirectory::TemporaryDirectory() {
    fs::path p{fs::temp_directory_path() / fs::unique_path()};
    fs::create_directories(p);
    path_ = p.string();
}

TemporaryDirectory::~TemporaryDirectory() { fs::remove_all(path_); }

}  // namespace silkworm
