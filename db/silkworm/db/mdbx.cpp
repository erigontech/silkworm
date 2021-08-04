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

#include "mdbx.hpp"

namespace silkworm::db {

::mdbx::env_managed open_env(const EnvConfig& config) {
    namespace fs = std::filesystem;

    if (config.path.empty()) {
        throw std::invalid_argument("Invalid argument : config.path");
    }

    // Check datafile exists if create is not set
    fs::path db_path{config.path};
    if (db_path.has_filename()) {
        db_path += std::filesystem::path::preferred_separator;  // Remove ambiguity. It has to be a directory
    }
    fs::path db_file{db::get_datafile_path(db_path)};
    if (!config.create) {
        if (!fs::exists(db_path) || !fs::is_directory(db_path) || fs::is_empty(db_path) || !fs::exists(db_file) ||
            !fs::is_regular_file(db_file) || !fs::file_size(db_file)) {
            throw std::runtime_error("Unable to locate " + db_file.string() + ". Must exist has been set");
        }
    } else {
        if (!fs::exists(db_path)) {
            fs::create_directories(db_path);
        } else {
            if (fs::exists(db_file)) {
                throw std::runtime_error("File " + db_file.string() + " already exists but create was set");
            }
        }
    }

    uint32_t flags{MDBX_NOTLS | MDBX_NORDAHEAD | MDBX_COALESCE | MDBX_SYNC_DURABLE};  // Default flags

    if (config.exclusive && config.shared) {
        throw std::runtime_error("Exlusive conflicts with Shared");
    }
    if (config.create && config.shared) {
        throw std::runtime_error("Create conflicts with Shared");
    }
    if (config.create && config.readonly) {
        throw std::runtime_error("Create conflicts with Readonly");
    }

    if (config.readonly) {
        flags |= MDBX_RDONLY;
    }
    if (config.inmemory) {
        flags |= MDBX_NOMETASYNC;
    }
    if (config.exclusive) {
        flags |= MDBX_EXCLUSIVE;
    }
    if (config.shared) {
        flags |= MDBX_ACCEDE;
    }

    ::mdbx::env_managed::create_parameters cp{};  // Default create parameters
    if (!(config.shared)) {
        size_t max_map_size{config.inmemory ? 64 * kMebi : 2 * kTebi};
        size_t growth_size{config.inmemory ? 2 * kMebi : 2 * kGibi};
        cp.geometry.make_dynamic(::mdbx::env::geometry::default_value, max_map_size);
        cp.geometry.growth_step = growth_size;
        cp.geometry.pagesize = 4 * kKibi;
    }

    ::mdbx::env::operate_parameters op{};  // Operational parameters
    op.mode = op.mode_from_flags(static_cast<MDBX_env_flags_t>(flags));
    op.options = op.options_from_flags(static_cast<MDBX_env_flags_t>(flags));
    op.durability = op.durability_from_flags(static_cast<MDBX_env_flags_t>(flags));
    op.max_maps = config.max_tables;
    op.max_readers = config.max_readers;

    ::mdbx::env_managed ret{db_path.native(), cp, op, config.shared};

    if (!config.shared) {
        // C++ bindings don't have setoptions
        ::mdbx::error::success_or_throw(::mdbx_env_set_option(ret, MDBX_opt_rp_augment_limit, 32 * kMebi));
        if (!config.readonly) {
            ::mdbx::error::success_or_throw(::mdbx_env_set_option(ret, MDBX_opt_txn_dp_initial, 16 * kKibi));
            ::mdbx::error::success_or_throw(::mdbx_env_set_option(ret, MDBX_opt_dp_reserve_limit, 16 * kKibi));

            uint64_t dirty_pages_limit{0};
            ::mdbx::error::success_or_throw(::mdbx_env_get_option(ret, MDBX_opt_txn_dp_limit, &dirty_pages_limit));
            ::mdbx::error::success_or_throw(::mdbx_env_set_option(ret, MDBX_opt_txn_dp_limit, dirty_pages_limit * 2));

            // must be in the range from 12.5% (almost empty) to 50% (half empty)
            // which corresponds to the range from 8192 and to 32768 in units respectively
            ::mdbx::error::success_or_throw(
                ::mdbx_env_set_option(ret, MDBX_opt_merge_threshold_16dot16_percent, 32768));
        }
    }
    if (!config.inmemory) {
        ret.check_readers();
    }
    return ret;
}

::mdbx::map_handle open_map(::mdbx::txn& tx, const MapConfig& config) {
    return tx.create_map(config.name, config.key_mode, config.value_mode);
}

::mdbx::cursor_managed open_cursor(::mdbx::txn& tx, const MapConfig& config) {
    return tx.open_cursor(open_map(tx, config));
}

size_t for_each(::mdbx::cursor& cursor, WalkFunc walker) {
    size_t ret{0};

    if (cursor.eof()) {
        // eof determines if cursor is positioned
        // at end of bucket data as well as it's
        // not positioned at all
        return ret;
    }

    auto data{cursor.current()};
    while (data.done) {
        const bool go_on{walker(data)};
        if (!go_on) {
            break;
        }
        ++ret;
        data = cursor.to_next(/*throw_notfound=*/false);
    }
    return ret;
}

size_t for_count(::mdbx::cursor& cursor, WalkFunc walker, size_t count) {
    size_t ret{0};

    if (cursor.eof()) {
        // eof determines if cursor is positioned
        // at end of bucket data as well as it's
        // not positioned at all
        return ret;
    }

    auto data{cursor.current()};
    while (count && data.done) {
        const bool go_on{walker(data)};
        if (!go_on) {
            break;
        }
        ++ret;
        --count;
        data = cursor.to_next(/*throw_notfound=*/false);
    }
    return ret;
}

}  // namespace silkworm::db
