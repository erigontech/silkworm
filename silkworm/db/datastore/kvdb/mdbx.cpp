// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "mdbx.hpp"

#include <stdexcept>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::datastore::kvdb {

namespace detail {
    std::string dump_mdbx_result(const CursorResult& result) {
        std::string dump{"done="};
        dump.append(std::to_string(result.done));
        dump.append(" bool(key)=");
        dump.append(std::to_string(bool{result.key}));
        dump.append(" bool(value)=");
        dump.append(std::to_string(bool{result.value}));
        return dump;
    }

    std::string slice_as_hex(const Slice& data) {
        return std::string(::mdbx::to_hex(data).as_string());
    }

    std::string slice_as_string(const Slice& data) {
        return std::string(data.as_string());
    }

    silkworm::Bytes slice_as_bytes(const Slice& data) {
        return silkworm::Bytes{reinterpret_cast<const unsigned char*>(data.data()), data.size()};
    }

    log::Args log_args_for_commit_latency(const MDBX_commit_latency& commit_latency) {
        return {
            "preparation",
            std::to_string(commit_latency.preparation),
            "write",
            std::to_string(commit_latency.write),
            "sync",
            std::to_string(commit_latency.sync),
            "ending",
            std::to_string(commit_latency.ending),
            "whole",
            std::to_string(commit_latency.whole),
        };
    }
}  // namespace detail

//! \brief Returns data of current cursor position or moves it to the beginning or the end of the table based on
//! provided direction if the cursor is not positioned.
//! \param [in] c : A reference to an open cursor
//! \param [in] d : Direction cursor should have \return ::mdbx::cursor::move_result
static CursorResult adjust_cursor_position_if_unpositioned(
    ROCursor& c, CursorMoveDirection d) {
    // Warning: eof() is not exactly what we need here since it returns true not only for cursors
    // that are not positioned, but also for those pointing to the end of data.
    // Unfortunately, there's no MDBX API to differentiate the two.
    if (c.eof()) {
        return (d == CursorMoveDirection::kForward) ? c.to_first(/*throw_notfound=*/false)
                                                    : c.to_last(/*throw_notfound=*/false);
    }
    return c.current(/*throw_notfound=*/false);
}

// Last entry whose key is strictly less than the given key
static CursorResult strict_lower_bound(ROCursor& cursor, const ByteView key) {
    if (!cursor.lower_bound(key, /*throw_notfound=*/false)) {
        // all DB keys are less than the given key
        return cursor.to_last(/*throw_notfound=*/false);
    }
    // return lower_bound - 1
    return cursor.to_previous(/*throw_notfound=*/false);
}

static mdbx::cursor::move_operation move_operation(CursorMoveDirection direction) {
    return direction == CursorMoveDirection::kForward
               ? mdbx::cursor::move_operation::next
               : mdbx::cursor::move_operation::previous;
}

::mdbx::env_managed open_env(const EnvConfig& config) {
    namespace fs = std::filesystem;

    if (config.path.empty()) {
        throw std::invalid_argument("Invalid argument : config.path");
    }

    // Check datafile exists if create is not set
    fs::path env_path{config.path};
    if (env_path.has_filename()) {
        env_path += std::filesystem::path::preferred_separator;  // Remove ambiguity. It has to be a directory
    }
    if (!fs::exists(env_path)) {
        fs::create_directories(env_path);
    } else if (!fs::is_directory(env_path)) {
        throw std::runtime_error("Path " + env_path.string() + " is not valid");
    }

    fs::path db_file{get_datafile_path(env_path)};
    const size_t db_file_size{fs::exists(db_file) ? fs::file_size(db_file) : 0};

    if (!config.create && !db_file_size) {
        throw std::runtime_error("Unable to locate " + db_file.string() + ", which is required to exist");
    }
    if (config.create && db_file_size) {
        throw std::runtime_error("File " + db_file.string() + " already exists but create was set");
    }

    // Prevent mapping a file with a smaller map size than the size on disk.
    // Opening would not fail but only a part of data would be mapped.
    if (db_file_size > config.max_size) {
        throw std::runtime_error("Database map size is too small. Min required " + human_size(db_file_size));
    }

    uint32_t flags{MDBX_NORDAHEAD | MDBX_SYNC_DURABLE};  // Default flags

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
    if (config.in_memory) {
        flags |= MDBX_NOMETASYNC;
    }
    if (config.exclusive) {
        flags |= MDBX_EXCLUSIVE;
    }
    if (config.shared) {
        flags |= MDBX_ACCEDE;
    }
    if (config.no_sticky_threads) {
        flags |= MDBX_NOSTICKYTHREADS;
    }
    if (config.write_map) {
        flags |= MDBX_WRITEMAP;
    }

    ::mdbx::env_managed::create_parameters cp{};  // Default create parameters
    if (!config.shared) {
        auto max_map_size = static_cast<intptr_t>(config.in_memory ? 128_Mebi : config.max_size);
        auto growth_size = static_cast<intptr_t>(config.in_memory ? 8_Mebi : config.growth_size);
        cp.geometry.make_dynamic(::mdbx::env::geometry::default_value, max_map_size);
        cp.geometry.growth_step = growth_size;
        if (!db_file_size) {
            cp.geometry.pagesize = static_cast<intptr_t>(config.page_size);
        }
    }

    using OP = ::mdbx::env::operate_parameters;
    OP op{};  // Operational parameters
    op.mode = OP::mode_from_flags(static_cast<MDBX_env_flags_t>(flags));
    op.options = OP::options_from_flags(static_cast<MDBX_env_flags_t>(flags));
    op.durability = OP::durability_from_flags(static_cast<MDBX_env_flags_t>(flags));
    op.max_maps = config.max_tables;
    op.max_readers = config.max_readers;

    ::mdbx::env_managed env{env_path.native(), cp, op, config.shared};

    // Read stats to make sure that env is fully functional,
    // otherwise there's an obscure bug:
    // mdbx::env::start_read fails with 22 (EINVAL) from fcntl on the mdbx lock file
    // (see branch debug_mdbx_txn_begin_fcntl_22 for a test case)
    [[maybe_unused]] auto _ = env.get_stat();

    if (!config.shared) {
        // C++ bindings don't have set_option
        ::mdbx::error::success_or_throw(::mdbx_env_set_option(env, MDBX_opt_rp_augment_limit, 32_Mebi));
        if (!config.readonly) {
            ::mdbx::error::success_or_throw(::mdbx_env_set_option(env, MDBX_opt_txn_dp_initial, 16_Kibi));
            ::mdbx::error::success_or_throw(::mdbx_env_set_option(env, MDBX_opt_dp_reserve_limit, 16_Kibi));

            uint64_t dirty_pages_limit{0};
            ::mdbx::error::success_or_throw(::mdbx_env_get_option(env, MDBX_opt_txn_dp_limit, &dirty_pages_limit));
            ::mdbx::error::success_or_throw(::mdbx_env_set_option(env, MDBX_opt_txn_dp_limit, dirty_pages_limit * 2));

            // must be in the range from 12.5% (almost empty) to 50% (half empty)
            // which corresponds to the range from 8192 and to 32768 in units respectively
            ::mdbx::error::success_or_throw(
                ::mdbx_env_set_option(env, MDBX_opt_merge_threshold_16dot16_percent, 32_Kibi));
        }
    }
    if (!config.in_memory) {
        env.check_readers();
    }
    return env;
}

::mdbx::map_handle open_map(::mdbx::txn& tx, const MapConfig& config) {
    if (tx.is_readonly()) {
        return tx.open_map(config.name_str(), config.key_mode, config.value_mode);
    }
    return tx.create_map(config.name_str(), config.key_mode, config.value_mode);
}

::mdbx::cursor_managed open_cursor(::mdbx::txn& tx, const MapConfig& config) {
    return tx.open_cursor(open_map(tx, config));
}

size_t max_value_size_for_leaf_page(const size_t page_size, const size_t key_size) {
    /*
     * On behalf of configured MDBX page size we need to find
     * the size of each shard best fitting in data page without
     * causing MDBX to write value in overflow pages.
     *
     * Example :
     *  for accounts history index
     *  with shard_key_len == kAddressLength + sizeof(uint64_t) == 28
     *  with page_size == 4096
     *  optimal shard size == 2000
     *
     *  for storage history index
     *  with shard_key_len == kAddressLength + kHashLength + sizeof(uint64_t) == 20 + 32 + 8 == 60
     *  with page_size == 4096
     *  optimal shard size == 1968
     *
     *  NOTE !! Keep an eye on MDBX code as PageHeader and Node structs might change
     */

    static constexpr size_t kPageOverheadSize{32ull};  // PageHeader + NodeSize
    const size_t page_room{page_size - kPageOverheadSize};
    const size_t leaf_node_max_room{
        ((page_room / 2) & ~1ull /* even number */) -
        (/* key and value sizes fields */ 2 * sizeof(uint16_t))};
    const size_t max_size{leaf_node_max_room - key_size};
    return max_size;
}

size_t max_value_size_for_leaf_page(const mdbx::txn& txn, const size_t key_size) {
    const size_t page_size{txn.env().get_pagesize()};
    return max_value_size_for_leaf_page(page_size, key_size);
}

std::unique_ptr<ROCursor> ROTxn::ro_cursor(const MapConfig& config) {
    return std::make_unique<PooledCursor>(*this, config);
}

std::unique_ptr<ROCursorDupSort> ROTxn::ro_cursor_dup_sort(const MapConfig& config) {
    return std::make_unique<PooledCursor>(*this, config);
}

std::unique_ptr<RWCursor> RWTxn::rw_cursor(const MapConfig& config) {
    return std::make_unique<PooledCursor>(*this, config);
}

std::unique_ptr<RWCursorDupSort> RWTxn::rw_cursor_dup_sort(const MapConfig& config) {
    return std::make_unique<PooledCursor>(*this, config);
}

void RWTxnManaged::commit_and_renew() {
    if (!commit_disabled_) {
        mdbx::env env = db();
        managed_txn_.commit();
        managed_txn_ = env.start_write();  // renew transaction
    }
}

void RWTxnManaged::commit_and_stop() {
    if (!commit_disabled_) {
        managed_txn_.commit();
    }
}

thread_local ObjectPool<MDBX_cursor, detail::CursorHandleDeleter> PooledCursor::handles_pool_{};

PooledCursor::PooledCursor() {
    handle_ = handles_pool_.acquire();
    if (!handle_) {
        handle_ = ::mdbx_cursor_create(nullptr);
    }
}

PooledCursor::PooledCursor(ROTxn& txn, ::mdbx::map_handle map) {
    handle_ = handles_pool_.acquire();
    if (!handle_) {
        handle_ = ::mdbx_cursor_create(nullptr);
    }
    bind(txn, map);
}

PooledCursor::PooledCursor(::mdbx::txn& txn, const MapConfig& config) {
    handle_ = handles_pool_.acquire();
    if (!handle_) {
        handle_ = ::mdbx_cursor_create(nullptr);
    }
    bind(txn, config);
}

PooledCursor::PooledCursor(PooledCursor&& other) noexcept { std::swap(handle_, other.handle_); }

PooledCursor& PooledCursor::operator=(PooledCursor&& other) noexcept {
    std::swap(handle_, other.handle_);
    return *this;
}

PooledCursor::~PooledCursor() {
    if (handle_) {
        handles_pool_.add(handle_);
    }
}

void PooledCursor::bind(ROTxn& txn, ::mdbx::map_handle map) {
    if (!handle_) throw std::runtime_error("cannot bind a closed cursor");
    // Check cursor is bound to a live transaction
    if (auto cm_tx{mdbx_cursor_txn(handle_)}; cm_tx) {
        // If current transaction id does not match cursor's transaction close it and recreate a new one
        if (txn->id() != mdbx_txn_id(cm_tx)) {
            close();
            handle_ = ::mdbx_cursor_create(nullptr);
        }
    }
    ::mdbx::cursor::bind(*txn, map);
}

void PooledCursor::bind(::mdbx::txn& txn, const MapConfig& config) {
    if (!handle_) throw std::runtime_error("cannot bind a closed cursor");
    // Check cursor is bound to a live transaction
    if (auto cm_tx{mdbx_cursor_txn(handle_)}; cm_tx) {
        // If current transaction id does not match cursor's transaction close it and recreate a new one
        if (txn.id() != mdbx_txn_id(cm_tx)) {
            close();
            handle_ = ::mdbx_cursor_create(nullptr);
        }
    }
    const auto map{open_map(txn, config)};
    ::mdbx::cursor::bind(txn, map);
}

std::unique_ptr<ROCursor> PooledCursor::clone() {
    auto clone = std::make_unique<PooledCursor>();
    mdbx::error::success_or_throw(::mdbx_cursor_copy(handle_, clone->handle_));
    return clone;
}

void PooledCursor::close() {
    ::mdbx_cursor_close(handle_);
    handle_ = nullptr;
}
MDBX_stat PooledCursor::get_map_stat() const {
    if (!handle_) {
        mdbx::error::success_or_throw(EINVAL);
    }
    return txn().get_map_stat(map());
}

MDBX_db_flags_t PooledCursor::get_map_flags() const {
    if (!handle_) {
        mdbx::error::success_or_throw(EINVAL);
    }
    return txn().get_handle_info(map()).flags;
}

bool PooledCursor::is_multi_value() const {
    return get_map_flags() & MDBX_DUPSORT;
}

bool PooledCursor::is_dangling() const {
    return eof() && !on_last();
}

size_t PooledCursor::size() const { return get_map_stat().ms_entries; }

::mdbx::map_handle PooledCursor::map() const {
    return ::mdbx::cursor::map();
}

CursorResult PooledCursor::to_first() {
    return ::mdbx::cursor::to_first(/*throw_notfound =*/true);
}

CursorResult PooledCursor::to_first(bool throw_notfound) {
    return ::mdbx::cursor::to_first(throw_notfound);
}

CursorResult PooledCursor::to_previous() {
    return ::mdbx::cursor::to_previous(/*throw_notfound =*/true);
}

CursorResult PooledCursor::to_previous(bool throw_notfound) {
    return ::mdbx::cursor::to_previous(throw_notfound);
}

CursorResult PooledCursor::current() const {
    return ::mdbx::cursor::current(/*throw_notfound =*/true);
}

CursorResult PooledCursor::current(bool throw_notfound) const {
    return ::mdbx::cursor::current(throw_notfound);
}

CursorResult PooledCursor::to_next() {
    return ::mdbx::cursor::to_next(/*throw_notfound =*/true);
}

CursorResult PooledCursor::to_next(bool throw_notfound) {
    return ::mdbx::cursor::to_next(throw_notfound);
}

CursorResult PooledCursor::to_last() {
    return ::mdbx::cursor::to_last(/*throw_notfound =*/true);
}

CursorResult PooledCursor::to_last(bool throw_notfound) {
    return ::mdbx::cursor::to_last(throw_notfound);
}

CursorResult PooledCursor::find(const Slice& key) {
    return ::mdbx::cursor::find(key, /*throw_notfound =*/true);
}

CursorResult PooledCursor::find(const Slice& key, bool throw_notfound) {
    return ::mdbx::cursor::find(key, throw_notfound);
}

CursorResult PooledCursor::lower_bound(const Slice& key) {
    return ::mdbx::cursor::lower_bound(key, /*throw_notfound =*/true);
}

CursorResult PooledCursor::lower_bound(const Slice& key, bool throw_notfound) {
    return ::mdbx::cursor::lower_bound(key, throw_notfound);
}

MoveResult PooledCursor::move(MoveOperation operation, bool throw_notfound) {
    return ::mdbx::cursor::move(operation, throw_notfound);
}

MoveResult PooledCursor::move(MoveOperation operation, const Slice& key, bool throw_notfound) {
    return ::mdbx::cursor::move(operation, key, throw_notfound);
}

bool PooledCursor::seek(const Slice& key) {
    return ::mdbx::cursor::seek(key);
}

bool PooledCursor::eof() const {
    return ::mdbx::cursor::eof();
}

bool PooledCursor::on_first() const {
    return ::mdbx::cursor::on_first();
}

bool PooledCursor::on_last() const {
    return ::mdbx::cursor::on_last();
}

CursorResult PooledCursor::to_previous_last_multi() {
    return ::mdbx::cursor::to_previous_last_multi(/*throw_notfound =*/true);
}

CursorResult PooledCursor::to_previous_last_multi(bool throw_notfound) {
    return ::mdbx::cursor::to_previous_last_multi(throw_notfound);
}

CursorResult PooledCursor::to_current_first_multi() {
    return ::mdbx::cursor::to_current_first_multi(/*throw_notfound =*/true);
}

CursorResult PooledCursor::to_current_first_multi(bool throw_notfound) {
    return ::mdbx::cursor::to_current_first_multi(throw_notfound);
}

CursorResult PooledCursor::to_current_prev_multi() {
    return ::mdbx::cursor::to_current_prev_multi(/*throw_notfound =*/true);
}

CursorResult PooledCursor::to_current_prev_multi(bool throw_notfound) {
    return ::mdbx::cursor::to_current_prev_multi(throw_notfound);
}

CursorResult PooledCursor::to_current_next_multi() {
    return ::mdbx::cursor::to_current_next_multi(/*throw_notfound =*/true);
}

CursorResult PooledCursor::to_current_next_multi(bool throw_notfound) {
    return ::mdbx::cursor::to_current_next_multi(throw_notfound);
}

CursorResult PooledCursor::to_current_last_multi() {
    return ::mdbx::cursor::to_current_last_multi(/*throw_notfound =*/true);
}

CursorResult PooledCursor::to_current_last_multi(bool throw_notfound) {
    return ::mdbx::cursor::to_current_last_multi(throw_notfound);
}

CursorResult PooledCursor::to_next_first_multi() {
    return ::mdbx::cursor::to_next_first_multi(/*throw_notfound =*/true);
}

CursorResult PooledCursor::to_next_first_multi(bool throw_notfound) {
    return ::mdbx::cursor::to_next_first_multi(throw_notfound);
}

CursorResult PooledCursor::find_multivalue(const Slice& key, const Slice& value) {
    return ::mdbx::cursor::find_multivalue(key, value, /*throw_notfound =*/true);
}

CursorResult PooledCursor::find_multivalue(const Slice& key, const Slice& value, bool throw_notfound) {
    return ::mdbx::cursor::find_multivalue(key, value, throw_notfound);
}

CursorResult PooledCursor::lower_bound_multivalue(const Slice& key, const Slice& value) {
    return ::mdbx::cursor::lower_bound_multivalue(key, value, /*throw_notfound =*/false);
}

CursorResult PooledCursor::lower_bound_multivalue(const Slice& key, const Slice& value, bool throw_notfound) {
    return ::mdbx::cursor::lower_bound_multivalue(key, value, throw_notfound);
}

MoveResult PooledCursor::move(MoveOperation operation, const Slice& key, const Slice& value, bool throw_notfound) {
    return ::mdbx::cursor::move(operation, key, value, throw_notfound);
}

size_t PooledCursor::count_multivalue() const {
    return ::mdbx::cursor::count_multivalue();
}

MDBX_error_t PooledCursor::put(const Slice& key, Slice* value, MDBX_put_flags_t flags) noexcept {
    return ::mdbx::cursor::put(key, value, flags);
}

void PooledCursor::insert(const Slice& key, Slice value) {
    ::mdbx::cursor::insert(key, value);
}

void PooledCursor::upsert(const Slice& key, const Slice& value) {
    ::mdbx::cursor::upsert(key, value);
}

void PooledCursor::update(const Slice& key, const Slice& value) {
    ::mdbx::cursor::update(key, value);
}

void PooledCursor::append(const Slice& key, const Slice& value) {
    Slice value_out = value;
    ::mdbx::error::success_or_throw(::mdbx::cursor::put(key, &value_out, MDBX_put_flags_t::MDBX_APPENDDUP));
}

bool PooledCursor::erase() {
    return ::mdbx::cursor::erase(/*whole_multivalue =*/false);
}

bool PooledCursor::erase(bool whole_multivalue) {
    return ::mdbx::cursor::erase(whole_multivalue);
}

bool PooledCursor::erase(const Slice& key) {
    return ::mdbx::cursor::erase(key, /*whole_multivalue =*/true);
}

bool PooledCursor::erase(const Slice& key, bool whole_multivalue) {
    return ::mdbx::cursor::erase(key, whole_multivalue);
}

bool PooledCursor::erase(const Slice& key, const Slice& value) {
    return ::mdbx::cursor::erase(key, value);
}

bool has_map(::mdbx::txn& tx, std::string_view map_name) {
    try {
        ::mdbx::map_handle main_map{1};
        auto main_cursor{tx.open_cursor(main_map)};
        auto found{main_cursor.seek(::mdbx::slice(map_name))};
        return found;
    } catch (const std::exception&) {
        return false;
    }
}

std::vector<std::string> list_maps(::mdbx::txn& tx, bool throw_notfound) {
    std::vector<std::string> map_names;
    ::mdbx::map_handle main_map{1};
    auto main_cursor{tx.open_cursor(main_map)};
    for (auto it{main_cursor.to_first(throw_notfound)}; it.done; it = main_cursor.to_next(throw_notfound)) {
        map_names.push_back(std::string(it.key.as_string()));
    }
    return map_names;
}

size_t cursor_for_each(ROCursor& cursor, WalkFuncRef walker, const CursorMoveDirection direction) {
    size_t ret{0};
    auto data{adjust_cursor_position_if_unpositioned(cursor, direction)};
    while (data) {
        ++ret;
        walker(from_slice(data.key), from_slice(data.value));
        data = cursor.move(move_operation(direction), /*throw_notfound=*/false);
    }
    return ret;
}

size_t cursor_for_prefix(ROCursor& cursor, const ByteView prefix, WalkFuncRef walker,
                         CursorMoveDirection direction) {
    size_t ret{0};
    auto data{cursor.lower_bound(prefix, false)};
    while (data) {
        if (!data.key.starts_with(prefix)) {
            break;
        }
        ++ret;
        walker(from_slice(data.key), from_slice(data.value));
        data = cursor.move(move_operation(direction), /*throw_notfound=*/false);
    }
    return ret;
}

size_t cursor_erase_prefix(RWCursor& cursor, const ByteView prefix) {
    size_t ret{0};
    auto data{cursor.lower_bound(prefix, /*throw_notfound=*/false)};
    while (data) {
        if (!data.key.starts_with(prefix)) {
            break;
        }
        ++ret;
        cursor.erase();
        data = cursor.to_next(/*throw_notfound=*/false);
    }
    return ret;
}

size_t cursor_for_count(ROCursor& cursor, WalkFuncRef walker, size_t count,
                        const CursorMoveDirection direction) {
    size_t ret{0};
    auto data{adjust_cursor_position_if_unpositioned(cursor, direction)};
    while (count && data.done) {
        ++ret;
        --count;
        walker(from_slice(data.key), from_slice(data.value));
        data = cursor.move(move_operation(direction), /*throw_notfound=*/false);
    }
    return ret;
}

size_t cursor_erase(RWCursor& cursor, const ByteView set_key, const CursorMoveDirection direction) {
    CursorResult data{
        direction == CursorMoveDirection::kForward
            ? cursor.lower_bound(set_key, /*throw_notfound=*/false)
            : strict_lower_bound(cursor, set_key)};

    size_t ret{0};
    while (data) {
        ++ret;
        cursor.erase();
        data = cursor.move(move_operation(direction), /*throw_notfound=*/false);
    }
    return ret;
}

}  // namespace silkworm::datastore::kvdb
