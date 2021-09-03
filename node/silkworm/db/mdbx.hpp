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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#include <mdbx.h++>
#pragma GCC diagnostic pop

#include <silkworm/common/base.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/db/util.hpp>

namespace silkworm::db {

constexpr std::string_view kDbDataFileName{"mdbx.dat"};
constexpr std::string_view kDbLockFileName{"mdbx.lck"};

//! \brief Pointer to a processing function invoked by cursor_for_each & cursor_for_count on each record
//! \remarks Return value signals whether the loop should continue on next record
using WalkFunc = std::function<bool(::mdbx::cursor::move_result&)>;

//! \brief Essential environment settings
struct EnvConfig {
    std::string path{};
    bool create{false};         // Whether db file must be created
    bool readonly{false};       // Whether db should be opened in RO mode
    bool exclusive{false};      // Whether this process has exclusive access
    bool inmemory{false};       // Whether this db is in memory
    bool shared{false};         // Whether this process opens a db already opened by another process
    uint32_t max_tables{128};   // Default max number of named tables
    uint32_t max_readers{100};  // Default max number of readers
};

//! \brief Configuration settings for a "map" (aka a table)
struct MapConfig {
    const char* name{nullptr};                                        // Name of the table (is key in MAIN_DBI)
    const ::mdbx::key_mode key_mode{::mdbx::key_mode::usual};         // Key collation order
    const ::mdbx::value_mode value_mode{::mdbx::value_mode::single};  // Data Storage Mode
};

//! \brief Opens an mdbx environment using the provided environment config
//! \param [in] config : A structure containing essential environment settings
//! \return A handler to mdbx::env_managed class
//! \remarks May throw exceptions
::mdbx::env_managed open_env(const EnvConfig& config);

//! \brief Opens an mdbx "map" (aka table)
//! \param [in] tx : a reference to a valid mdbx transaction
//! \param [in] config : the configuration settings for the map
//! \return A handle to the opened map
::mdbx::map_handle open_map(::mdbx::txn& tx, const MapConfig& config);

//! \brief Opens a cursor to an mdbx "map" (aka table)
//! \param [in] tx : a reference to a valid mdbx transaction
//! \param [in] config : the configuration settings for the underlying map
//! \return A handle to the opened cursor
::mdbx::cursor_managed open_cursor(::mdbx::txn& tx, const MapConfig& config);

//! \brief Checks whether a provided map name exists in database
//! \param [in] tx : a reference to a valid mdbx transaction
//! \param [in] map_name : the name of the map to check for
//! \return True / False
bool has_map(::mdbx::txn& tx, const char* map_name);

//! \brief Builds the full path to mdbx datafile provided a directory
//! \param [in] base_path : a reference to the directory holding the data file
//! \return A path with file name
static inline std::filesystem::path get_datafile_path(const std::filesystem::path& base_path) noexcept {
    return std::filesystem::path(base_path / std::filesystem::path(kDbDataFileName));
}

//! \brief Builds the full path to mdbx lockfile provided a directory
//! \param [in] base_path : a reference to the directory holding the lock file
//! \return A path with file name
static inline std::filesystem::path get_lockfile_path(const std::filesystem::path& base_path) noexcept {
    return std::filesystem::path(base_path / std::filesystem::path(kDbLockFileName));
}

//! \brief Defines the direction of cursor while looping by cursor_for_each or cursor_for_count
enum class CursorMoveDirection { Forward, Reverse };

//! \brief Executes a function on each record reachable by the provided cursor
//! \param [in] cursor : A reference to a cursor opened on a map
//! \param [in] func : A pointer to a std::function with the code to execute on records. Note the return value of the
//! function may stop the loop
//! \param [in] direction : Whether the cursor should navigate records forward (default) or backwards
//! \return The overall number of processed records
//! \remarks If the provided cursor is *not* positioned on any record it will be moved to either the beginning or the
//! end of the table on behalf of the move criteria
size_t cursor_for_each(::mdbx::cursor& cursor, WalkFunc func, CursorMoveDirection direction = CursorMoveDirection::Forward);

//! \brief Executes a function on each record reachable by the provided cursor up to a max number of iterations
//! \param [in] cursor : A reference to a cursor opened on a map
//! \param [in] func : A pointer to a std::function with the code to execute on records. Note the return value of the
//! function may stop the loop
//! \param [in] max_count : Max number of iterations
//! \param [in] direction : Whether the cursor should navigate records forward (default) or backwards
//! \return The overall number of processed records. Should it not match the value of max_count it means the cursor has
//! reached either the end or the beginning of table earlier
//! \remarks If the provided cursor is *not* positioned on any record it will be moved to either the beginning or the
//! end of the table on behalf of the move criteria
size_t cursor_for_count(::mdbx::cursor& cursor, WalkFunc func, size_t max_count,
                 CursorMoveDirection direction = CursorMoveDirection::Forward);

}  // namespace silkworm::db

#endif  // !SILKWORM_DB_MDBX_HPP_
