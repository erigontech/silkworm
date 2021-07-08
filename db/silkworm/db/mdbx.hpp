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

#ifndef SILKWORM_DB_MDBX_HPP_
#define SILKWORM_DB_MDBX_HPP_

#include <stdint.h>

#include <filesystem>
#include <string>

#include <silkworm/common/base.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/db/util.hpp>

#include "../libmdbx/mdbx.h++"

namespace silkworm::db {

constexpr std::string_view kDb_data_file_name{"mdbx.dat"};
constexpr std::string_view kDb_lock_file_name{"mdbx.lck"};

struct EnvConfig {
    std::string path{};
    uint32_t flags{MDBX_NOTLS | MDBX_NORDAHEAD | MDBX_COALESCE | MDBX_ACCEDE};  // Default flags
    uint32_t max_tables{128};                                                   // Default max number of named tables
    uint32_t max_readers{100};                                                  // Default max number of readers
    void set_readonly(bool value);                                              // Sets/unsets readonly flag
    void set_exclusive(bool value);                                             // Sets/unsets exclusive flag
    void set_in_mem(bool value);                                                // Sets/unsets in memory
};

struct MapConfig {
    const char* name{nullptr};                                        // Name of the table (is key in MAIN_DBI)
    const ::mdbx::key_mode key_mode{::mdbx::key_mode::usual};         // Key collation order
    const ::mdbx::value_mode value_mode{::mdbx::value_mode::single};  // Data Storage Mode
};

::mdbx::env_managed open_env(const EnvConfig& config);
::mdbx::map_handle open_map(::mdbx::txn& tx, const MapConfig& config);
::mdbx::cursor_managed open_cursor(::mdbx::txn& tx, const MapConfig& config);

static inline std::filesystem::path get_datafile_path(std::filesystem::path& base_path) noexcept {
    return std::filesystem::path(base_path / std::filesystem::path(kDb_data_file_name));
}

static inline std::filesystem::path get_lockfile_path(std::filesystem::path& base_path) noexcept {
    return std::filesystem::path(base_path / std::filesystem::path(kDb_lock_file_name));
}

}  // namespace silkworm::db

#endif  // !SILKWORM_DB_MDBX_HPP_
