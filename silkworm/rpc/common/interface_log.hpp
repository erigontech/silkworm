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

#pragma once

#include <cstddef>
#include <filesystem>
#include <memory>
#include <string_view>

#include <silkworm/core/common/base.hpp>

namespace silkworm::log {

class InterfaceLogImpl;

struct InterfaceLogConfig {
    bool enabled{false};
    std::string ifc_name;
    std::string container_folder{"logs/"};
    std::size_t max_file_size{1 * kMebi};
    std::size_t max_files{100};
    bool auto_flush{false};
};

class InterfaceLog final {
  public:
    explicit InterfaceLog(InterfaceLogConfig config);
    ~InterfaceLog();

    [[nodiscard]] std::filesystem::path path() const;

    void log_req(std::string_view msg);
    void log_rsp(std::string_view msg);

    void flush();

  private:
    std::unique_ptr<InterfaceLogImpl> p_impl_;
};

}  // namespace silkworm::log
