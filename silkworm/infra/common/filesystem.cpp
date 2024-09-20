/*
   Copyright 2024 The Silkworm Authors

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

#include "filesystem.hpp"

namespace silkworm {

void move_file(const std::filesystem::path& path, const std::filesystem::path& target_dir_path) {
    std::filesystem::rename(path, target_dir_path / path.filename());
}

void move_files(const std::vector<std::filesystem::path>& paths, const std::filesystem::path& target_dir_path) {
    for (const std::filesystem::path& path : paths) {
        move_file(path, target_dir_path);
    }
}

}  // namespace silkworm
