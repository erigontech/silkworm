/*
   Copyright 2021-2022 The Silkworm Authors

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

namespace detail {

    //! \brief Returns data of current cursor position or moves it to the beginning or the end of the table based on
    //! provided direction if the cursor is not positioned.
    //! \param [in] c : A reference to an open cursor
    //! \param [in] d : Direction cursor should have \return ::mdbx::cursor::move_result
    static inline ::mdbx::cursor::move_result adjust_cursor_position_if_unpositioned_and_return_data(
        ::mdbx::cursor& c, CursorMoveDirection d) {
        // Warning: eof() is not exactly what we need here since it returns true not only for cursors
        // that are not positioned, but also for those pointing to the end of data.
        // Unfortunately, there's no MDBX API to differentiate the two.
        if (c.eof()) {
            return (d == CursorMoveDirection::Forward) ? c.to_first(/*throw_notfound=*/false)
                                                       : c.to_last(/*throw_notfound=*/false);
        }
        return c.current(/*throw_notfound=*/false);
    }

    static bool cursor_erase_data(::mdbx::cursor& cursor, ::mdbx::cursor::move_result& data) {
        (void)data;
        return cursor.erase();
    }

}  // namespace detail

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
    if (!fs::exists(db_path)) {
        fs::create_directories(db_path);
    } else if (!fs::is_directory(db_path)) {
        throw std::runtime_error("Path " + db_path.string() + " is not valid");
    }

    fs::path db_file{db::get_datafile_path(db_path)};
    size_t db_ondisk_file_size{fs::exists(db_file) ? fs::file_size(db_file) : 0};

    if (!config.create && !db_ondisk_file_size) {
        throw std::runtime_error("Unable to locate " + db_file.string() + ", which is required to exist");
    } else if (config.create && db_ondisk_file_size) {
        throw std::runtime_error("File " + db_file.string() + " already exists but create was set");
    }

    // Prevent mapping a file with a smaller map size than the size on disk.
    // Opening would not fail but only a part of data would be mapped.
    if (db_ondisk_file_size > config.max_size) {
        throw std::runtime_error("Database map size is too small. Min required " + human_size(db_ondisk_file_size));
    }

    uint32_t flags{MDBX_NOTLS | MDBX_NORDAHEAD | MDBX_COALESCE | MDBX_SYNC_DURABLE};  // Default flags

    if (config.read_ahead) {
        flags &= ~MDBX_NORDAHEAD;
    }
    if (config.exclusive && config.shared) {
        throw std::runtime_error("Exclusive conflicts with Shared");
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
    if (config.write_map) {
        flags |= MDBX_WRITEMAP;
    }

    ::mdbx::env_managed::create_parameters cp{};  // Default create parameters
    if (!config.shared) {
        auto max_map_size = static_cast<intptr_t>(config.inmemory ? 64_Mebi : config.max_size);
        auto growth_size = static_cast<intptr_t>(config.inmemory ? 2_Mebi : config.growth_size);
        cp.geometry.make_dynamic(::mdbx::env::geometry::default_value, max_map_size);
        cp.geometry.growth_step = growth_size;
        cp.geometry.pagesize = 4_Kibi;
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
        ::mdbx::error::success_or_throw(::mdbx_env_set_option(ret, MDBX_opt_rp_augment_limit, 32_Mebi));
        if (!config.readonly) {
            ::mdbx::error::success_or_throw(::mdbx_env_set_option(ret, MDBX_opt_txn_dp_initial, 16_Kibi));
            ::mdbx::error::success_or_throw(::mdbx_env_set_option(ret, MDBX_opt_dp_reserve_limit, 16_Kibi));

            uint64_t dirty_pages_limit{0};
            ::mdbx::error::success_or_throw(::mdbx_env_get_option(ret, MDBX_opt_txn_dp_limit, &dirty_pages_limit));
            ::mdbx::error::success_or_throw(::mdbx_env_set_option(ret, MDBX_opt_txn_dp_limit, dirty_pages_limit * 2));

            // must be in the range from 12.5% (almost empty) to 50% (half empty)
            // which corresponds to the range from 8192 and to 32768 in units respectively
            ::mdbx::error::success_or_throw(
                ::mdbx_env_set_option(ret, MDBX_opt_merge_threshold_16dot16_percent, 32_Kibi));
        }
    }
    if (!config.inmemory) {
        ret.check_readers();
    }
    return ret;
}

::mdbx::map_handle open_map(::mdbx::txn& tx, const MapConfig& config) {
    if (tx.is_readonly()) {
        return tx.open_map(config.name, config.key_mode, config.value_mode);
    }
    return tx.create_map(config.name, config.key_mode, config.value_mode);
}

::mdbx::cursor_managed open_cursor(::mdbx::txn& tx, const MapConfig& config) {
    return tx.open_cursor(open_map(tx, config));
}

thread_local ObjectPool<MDBX_cursor, detail::cursor_handle_deleter> Cursor::handles_pool_{};

Cursor::Cursor(::mdbx::txn& txn, const MapConfig& config) {
    handle_ = handles_pool_.acquire();
    if (!handle_) {
        handle_ = ::mdbx_cursor_create(nullptr);
    }
    bind(txn, config);
}

Cursor::Cursor(Cursor&& other) noexcept { std::swap(handle_, other.handle_); }

Cursor& Cursor::operator=(Cursor&& other) noexcept {
    std::swap(handle_, other.handle_);
    return *this;
}

Cursor::~Cursor() {
    if (handle_) {
        handles_pool_.add(handle_);
    }
}

void Cursor::bind(::mdbx::txn& txn, const MapConfig& config) {
    // Check cursor is bound to a live transaction
    if (auto cm_tx{mdbx_cursor_txn(handle_)}; cm_tx) {
        // If current transaction id does not match cursor's transaction close it
        // and recreate a new one
        if (txn.id() != mdbx_txn_id(cm_tx)) {
            close();
            handle_ = ::mdbx_cursor_create(nullptr);
        }
    }
    const auto map{open_map(txn, config)};
    ::mdbx::cursor::bind(txn, map);
}

void Cursor::close() {
    ::mdbx_cursor_close(handle_);
    handle_ = nullptr;
}
MDBX_stat Cursor::get_map_stat() const {
    if (!handle_) {
        mdbx::error::success_or_throw(EINVAL);
    }
    return txn().get_map_stat(map());
}

bool has_map(::mdbx::txn& tx, const char* map_name) {
    try {
        ::mdbx::map_handle main_map{1};
        auto main_crs{tx.open_cursor(main_map)};
        auto found{main_crs.seek(::mdbx::slice(map_name))};
        return found;
    } catch (const std::exception&) {
        return false;
    }
}

size_t cursor_for_each(::mdbx::cursor& cursor, const WalkFunc& walker, const CursorMoveDirection direction) {
    const mdbx::cursor::move_operation move_operation{direction == CursorMoveDirection::Forward
                                                          ? mdbx::cursor::move_operation::next
                                                          : mdbx::cursor::move_operation::previous};

    size_t ret{0};
    auto data{detail::adjust_cursor_position_if_unpositioned_and_return_data(cursor, direction)};
    while (data.done) {
        ++ret;
        if (!walker(cursor, data)) {
            break;  // Walker function has returned false hence stop
        }
        data = cursor.move(move_operation, /*throw_notfound=*/false);
    }
    return ret;
}

size_t cursor_for_count(::mdbx::cursor& cursor, const WalkFunc& walker, size_t count,
                        const CursorMoveDirection direction) {
    const mdbx::cursor::move_operation move_operation{direction == CursorMoveDirection::Forward
                                                          ? mdbx::cursor::move_operation::next
                                                          : mdbx::cursor::move_operation::previous};
    size_t ret{0};
    auto data{detail::adjust_cursor_position_if_unpositioned_and_return_data(cursor, direction)};
    while (count && data.done) {
        ++ret;
        --count;
        if (!walker(cursor, data)) {
            break;  // Walker function has returned false hence stop
        }
        data = cursor.move(move_operation, /*throw_notfound=*/false);
    }
    return ret;
}

size_t cursor_erase(mdbx::cursor& cursor, const CursorMoveDirection direction) {
    return cursor_for_each(cursor, detail::cursor_erase_data, direction);
}

size_t cursor_erase(mdbx::cursor& cursor, const ByteView& set_key, const CursorMoveDirection direction) {
    // Search lower bound key
    if (!cursor.lower_bound(to_slice(set_key), false)) {
        return 0;
    }
    // In reverse direction move to lower key
    if (direction == CursorMoveDirection::Reverse && !cursor.to_previous(false)) {
        return 0;
    }
    return cursor_for_each(cursor, detail::cursor_erase_data, direction);
}

size_t cursor_erase(mdbx::cursor& cursor, size_t max_count, const CursorMoveDirection direction) {
    return cursor_for_count(cursor, detail::cursor_erase_data, max_count, direction);
}

size_t cursor_erase(mdbx::cursor& cursor, const ByteView& set_key, size_t max_count,
                    const CursorMoveDirection direction) {
    // Search lower bound key
    if (!cursor.lower_bound(to_slice(set_key), false)) {
        return 0;
    }
    // In reverse direction move to lower key
    if (direction == CursorMoveDirection::Reverse && !cursor.to_previous(false)) {
        return 0;
    }
    return cursor_for_count(cursor, detail::cursor_erase_data, max_count, direction);
}

}  // namespace silkworm::db
