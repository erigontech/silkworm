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

#ifndef SILKWORM_COMMON_TEMP_DIR_H_
#define SILKWORM_COMMON_TEMP_DIR_H_

#include <string>

namespace silkworm {

// Creates a temporary directory on construction and removes it on destruction.
class TemporaryDirectory {
   public:
    TemporaryDirectory();
    ~TemporaryDirectory();

    const char* path() const noexcept { return path_.c_str(); }

   private:
    std::string path_;
};

}  // namespace silkworm

#endif  // SILKWORM_COMMON_TEMP_DIR_H_
