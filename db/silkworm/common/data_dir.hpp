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

#ifndef SILKWORM_COMMON_DATA_DIR_HPP_
#define SILKWORM_COMMON_DATA_DIR_HPP_

#include <filesystem>

namespace silkworm {

class DataDirectory {
  public:
    explicit DataDirectory(const std::filesystem::path& base_path, bool create = false);
    explicit DataDirectory(bool create = false)
        : DataDirectory::DataDirectory(DataDirectory::get_default_storage_path(), create) {}
    explicit DataDirectory(const char* base_path, bool create = false)
        : DataDirectory::DataDirectory(std::filesystem::path(base_path), create) {}

    // Creates an instance of DataDirectory from chaindata path
    static DataDirectory from_chaindata(std::filesystem::path chaindata_path);

    // Returns the default storage path (from env vars)
    static std::filesystem::path get_default_storage_path();

    // Creates the directory structure
    void create_tree();

    // Clears contents of etl-temp directory
    void clear_etl_temp();

    // Returns validity of this data directory
    bool valid() const { return valid_; }

    const std::filesystem::path& get_base_path() const { return base_path_; }
    const std::filesystem::path& get_chaindata_path() const { return chaindata_path_; }
    const std::filesystem::path& get_nodes_path() const { return nodes_path_; }
    const std::filesystem::path& get_etl_path() const { return etl_temp_path_; }

  private:
    bool valid_{false};                     // Whether or not this data directory is valid
    std::filesystem::path base_path_;       // Provided base path or default storage path
    std::filesystem::path chaindata_path_;  // Path to chaindata
    std::filesystem::path nodes_path_;      // Path to nodes
    std::filesystem::path etl_temp_path_;   // Path to etl temporary directory
};

}  // namespace silkworm
#endif  // !SILKWORM_COMMON_TEMP_DIR_HPP_
