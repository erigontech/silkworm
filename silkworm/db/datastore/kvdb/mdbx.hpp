// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#include <mdbx.h++>
#pragma GCC diagnostic pop

#include <utility>

#include <absl/functional/function_ref.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/object_pool.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/os.hpp>

namespace silkworm::datastore::kvdb {

inline constexpr std::string_view kDbDataFileName{"mdbx.dat"};

inline constexpr size_t kMdbxMaxPages{2147483648ull};

using MoveOperation = ::mdbx::cursor::move_operation;
using CursorResult = ::mdbx::pair_result;
using MoveResult = ::mdbx::cursor::move_result;
using Slice = ::mdbx::slice;

//! Comparison operator for CursorResult taking care to compare keys and values only *after*
//! checking the `done` flag to avoid comparing uninitialized key/value slices
inline bool operator==(const CursorResult& lhs, const CursorResult& rhs) noexcept {
    if (lhs.done != rhs.done) return false;
    if (lhs.done) {
        if (lhs.key && rhs.key && lhs.key != rhs.key) {
            return false;
        }
        if (lhs.value && rhs.value) {
            return lhs.value == rhs.value;
        }
    }
    return true;
}

namespace detail {
    struct CursorHandleDeleter {  // default deleter for pooled cursors
        constexpr CursorHandleDeleter() noexcept = default;
        void operator()(MDBX_cursor* ptr) const noexcept { mdbx_cursor_close(ptr); }
    };

    std::string dump_mdbx_result(const CursorResult& result);
    std::string slice_as_hex(const Slice& data);
}  // namespace detail

class ROTxn;
struct MapConfig;

//! \brief Read-only key-value cursor for single-value tables
class ROCursor {
  public:
    virtual ~ROCursor() = default;

    //! \brief Reuse current cursor binding it to provided transaction and map configuration
    virtual void bind(ROTxn& txn, const MapConfig& config) = 0;

    //! \brief Clone cursor position and state
    virtual std::unique_ptr<ROCursor> clone() = 0;

    //! \brief Returns the size of the underlying table
    virtual size_t size() const = 0;

    //! \brief Returns whether the underlying table is empty
    bool empty() const { return size() == 0; }

    //! \brief Flag indicating if table is single-value or multi-value
    virtual bool is_multi_value() const = 0;

    //! \brief Flag indicating if cursor has been positioned or not
    virtual bool is_dangling() const = 0;

    //! \brief Escape hatch returning the underlying MDBX map handle
    virtual ::mdbx::map_handle map() const = 0;

    virtual CursorResult to_first() = 0;
    virtual CursorResult to_first(bool throw_notfound) = 0;
    virtual CursorResult to_previous() = 0;
    virtual CursorResult to_previous(bool throw_notfound) = 0;
    virtual CursorResult current() const = 0;
    virtual CursorResult current(bool throw_notfound) const = 0;
    virtual CursorResult to_next() = 0;
    virtual CursorResult to_next(bool throw_notfound) = 0;
    virtual CursorResult to_last() = 0;
    virtual CursorResult to_last(bool throw_notfound) = 0;
    virtual CursorResult find(const Slice& key) = 0;
    virtual CursorResult find(const Slice& key, bool throw_notfound) = 0;
    virtual CursorResult lower_bound(const Slice& key) = 0;
    virtual CursorResult lower_bound(const Slice& key, bool throw_notfound) = 0;
    virtual MoveResult move(MoveOperation operation, bool throw_notfound) = 0;
    virtual MoveResult move(MoveOperation operation, const Slice& key, bool throw_notfound) = 0;
    virtual bool seek(const Slice& key) = 0;
    virtual bool eof() const = 0;
    virtual bool on_first() const = 0;
    virtual bool on_last() const = 0;
};

//! \brief Read-only key-value cursor for multi-value tables
class ROCursorDupSort : public virtual ROCursor {
  public:
    ~ROCursorDupSort() override = default;

    virtual CursorResult to_previous_last_multi() = 0;
    virtual CursorResult to_previous_last_multi(bool throw_notfound) = 0;
    virtual CursorResult to_current_first_multi() = 0;
    virtual CursorResult to_current_first_multi(bool throw_notfound) = 0;
    virtual CursorResult to_current_prev_multi() = 0;
    virtual CursorResult to_current_prev_multi(bool throw_notfound) = 0;
    virtual CursorResult to_current_next_multi() = 0;
    virtual CursorResult to_current_next_multi(bool throw_notfound) = 0;
    virtual CursorResult to_current_last_multi() = 0;
    virtual CursorResult to_current_last_multi(bool throw_notfound) = 0;
    virtual CursorResult to_next_first_multi() = 0;
    virtual CursorResult to_next_first_multi(bool throw_notfound) = 0;
    virtual CursorResult find_multivalue(const Slice& key, const Slice& value) = 0;
    virtual CursorResult find_multivalue(const Slice& key, const Slice& value, bool throw_notfound) = 0;
    virtual CursorResult lower_bound_multivalue(const Slice& key, const Slice& value) = 0;
    virtual CursorResult lower_bound_multivalue(const Slice& key, const Slice& value, bool throw_notfound) = 0;
    MoveResult move(MoveOperation operation, bool throw_notfound) override = 0;
    MoveResult move(MoveOperation operation, const Slice& key, bool throw_notfound) override = 0;
    virtual MoveResult move(MoveOperation operation, const Slice& key, const Slice& value, bool throw_notfound) = 0;
    virtual size_t count_multivalue() const = 0;
};

//! \brief Read-write key-value cursor for single-value tables
class RWCursor : public virtual ROCursor {
  public:
    ~RWCursor() override = default;

    virtual MDBX_error_t put(const Slice& key, Slice* value, MDBX_put_flags_t flags) noexcept = 0;
    virtual void insert(const Slice& key, Slice value) = 0;
    virtual void upsert(const Slice& key, const Slice& value) = 0;
    virtual void update(const Slice& key, const Slice& value) = 0;

    //! \brief Remove single key-value pair at the current cursor position.
    virtual bool erase() = 0;
    virtual bool erase(bool whole_multivalue) = 0;

    //! \brief Seek and remove first value of the given key.
    //! \return true if the key is found and a value(s) is removed.
    virtual bool erase(const Slice& key) = 0;
    virtual bool erase(const Slice& key, bool whole_multivalue) = 0;
};

//! \brief Read-write key-value cursor for multi-value tables
class RWCursorDupSort : public RWCursor, public ROCursorDupSort {
  public:
    ~RWCursorDupSort() override = default;

    virtual void append(const Slice& key, const Slice& value) = 0;

    //! \brief Remove all multi-values at the current cursor position.
    bool erase() override = 0;
    bool erase(bool whole_multivalue) override = 0;

    //! \brief Seek and remove whole multi-value of the given key.
    //! \return true if the key is found and a value(s) is removed.
    bool erase(const Slice& key) override = 0;
    bool erase(const Slice& key, bool whole_multivalue) override = 0;

    //! \brief Seek and remove the particular multi-value entry of the key.
    //! \return true if the given key-value pair is found and removed
    virtual bool erase(const Slice& key, const Slice& value) = 0;
};

//! \brief Configuration settings for a "map" (aka a table)
struct MapConfig {
    const char* name{nullptr};                                        // Name of the table (is key in MAIN_DBI)
    const ::mdbx::key_mode key_mode{::mdbx::key_mode::usual};         // Key collation order
    const ::mdbx::value_mode value_mode{::mdbx::value_mode::single};  // Data Storage Mode
};

//! \brief ROTxn represents a read-only transaction.
//! It is used in function signatures to clarify that read-only access is sufficient, read-write access is not required.
class ROTxn {
  public:
    virtual ~ROTxn() = default;

    // Access to the underling raw mdbx transaction
    mdbx::txn& operator*() { return txn_ref_; }
    mdbx::txn* operator->() { return &txn_ref_; }
    operator mdbx::txn&() { return txn_ref_; }  // NOLINT(google-explicit-constructor, hicpp-explicit-conversions)

    uint64_t id() const { return txn_ref_.id(); }
    virtual bool is_open() const { return txn_ref_.txn::operator bool(); }
    virtual mdbx::env db() const { return txn_ref_.env(); }

    virtual std::unique_ptr<ROCursor> ro_cursor(const MapConfig& config);
    virtual std::unique_ptr<ROCursorDupSort> ro_cursor_dup_sort(const MapConfig& config);

    virtual void abort() = 0;

  protected:
    explicit ROTxn(::mdbx::txn& txn_ref) : txn_ref_{txn_ref} {}

  private:
    ::mdbx::txn& txn_ref_;
};

//! \brief ROTxnManaged wraps a *managed* read-only transaction, which means the underlying transaction lifecycle
//! is entirely managed by this class.
class ROTxnManaged : public ROTxn {
  public:
    explicit ROTxnManaged() : ROTxn{managed_txn_} {}
    explicit ROTxnManaged(mdbx::env& env) : ROTxn{managed_txn_}, managed_txn_{env.start_read()} {}
    explicit ROTxnManaged(mdbx::env&& env) : ROTxn{managed_txn_}, managed_txn_{std::move(env).start_read()} {}
    ~ROTxnManaged() override = default;

    // Not copyable
    ROTxnManaged(const ROTxnManaged&) = delete;
    ROTxnManaged& operator=(const ROTxnManaged&) = delete;

    // Only movable
    ROTxnManaged(ROTxnManaged&& source) noexcept : ROTxn{managed_txn_}, managed_txn_{std::move(source.managed_txn_)} {}
    ROTxnManaged& operator=(ROTxnManaged&& other) noexcept {
        managed_txn_ = std::move(other.managed_txn_);
        return *this;
    }

    void abort() override { managed_txn_.abort(); }

  protected:
    explicit ROTxnManaged(mdbx::txn_managed&& source) : ROTxn{managed_txn_}, managed_txn_{std::move(source)} {}

    mdbx::txn_managed managed_txn_;
};

//! \brief ROTxnUnmanaged wraps an *unmanaged* read-only transaction, which means the underlying transaction
//! lifecycle is not touched by this class. This implies that this class does not abort the transaction.
class ROTxnUnmanaged : public ROTxn, protected ::mdbx::txn {
  public:
    explicit ROTxnUnmanaged(MDBX_txn* ptr) : ROTxn{static_cast<::mdbx::txn&>(*this)}, ::mdbx::txn{ptr} {}
    ~ROTxnUnmanaged() override = default;

    void abort() override {}
};

//! \brief This class wraps a read-write transaction.
//! It is used in function signatures to clarify that read-write access is required.
//! It supports explicit disable/enable of commit capabilities.
//! Disabling commit is useful for running several stages on a handful of blocks atomically.
class RWTxn : public ROTxn {
  public:
    ~RWTxn() override = default;

    bool commit_disabled() const { return commit_disabled_; }

    void disable_commit() { commit_disabled_ = true; }
    void enable_commit() { commit_disabled_ = false; }

    virtual std::unique_ptr<RWCursor> rw_cursor(const MapConfig& config);
    virtual std::unique_ptr<RWCursorDupSort> rw_cursor_dup_sort(const MapConfig& config);

    virtual void commit_and_renew() = 0;
    virtual void commit_and_stop() = 0;

  protected:
    explicit RWTxn(::mdbx::txn& txn_ref, bool commit_disabled = false)
        : ROTxn{txn_ref}, commit_disabled_{commit_disabled} {}

    bool commit_disabled_;
};

//! \brief RWTxnManaged wraps a *managed* read-write transaction, which means the underlying transaction lifecycle
//! is entirely managed by this class.
class RWTxnManaged : public RWTxn {
  public:
    explicit RWTxnManaged() : RWTxn{managed_txn_} {}
    explicit RWTxnManaged(mdbx::env& env) : RWTxn{managed_txn_}, managed_txn_{env.start_write()} {}
    explicit RWTxnManaged(mdbx::env&& env) : RWTxn{managed_txn_}, managed_txn_{std::move(env).start_write()} {}
    ~RWTxnManaged() override = default;

    // Not copyable
    RWTxnManaged(const RWTxnManaged&) = delete;
    RWTxnManaged& operator=(const RWTxnManaged&) = delete;

    // Only movable
    RWTxnManaged(RWTxnManaged&& source) noexcept
        : RWTxn{managed_txn_, source.commit_disabled_}, managed_txn_{std::move(source.managed_txn_)} {}
    RWTxnManaged& operator=(RWTxnManaged&& other) noexcept {
        commit_disabled_ = other.commit_disabled_;
        managed_txn_ = std::move(other.managed_txn_);
        return *this;
    }

    void abort() override { managed_txn_.abort(); }

    void commit_and_renew() override;
    void commit_and_stop() override;

    void reopen(mdbx::env& env) { managed_txn_ = env.start_write(); }

  protected:
    explicit RWTxnManaged(mdbx::txn_managed&& source) : RWTxn{managed_txn_}, managed_txn_{std::move(source)} {}

    mdbx::txn_managed managed_txn_;
};

//! \brief RWTxnUnmanaged wraps an *unmanaged* read-write transaction, which means the underlying transaction
//! lifecycle is not touched by this class: the transaction is neither committed nor aborted.
class RWTxnUnmanaged : public RWTxn, protected ::mdbx::txn {
  public:
    explicit RWTxnUnmanaged(MDBX_txn* ptr) : RWTxn{static_cast<::mdbx::txn&>(*this)}, ::mdbx::txn{ptr} {}
    ~RWTxnUnmanaged() override = default;

    void abort() override { throw std::runtime_error{"RWTxnUnmanaged must not be aborted"}; }
    void commit_and_renew() override { throw std::runtime_error{"RWTxnUnmanaged must not be committed"}; }
    void commit_and_stop() override { throw std::runtime_error{"RWTxnUnmanaged must not be committed"}; }
};

//! \brief This class create ROTxn(s) on demand, it is used to enforce in some method signatures the type of db access
class ROAccess {
  public:
    explicit ROAccess(const mdbx::env& env) : env_{env} {}
    explicit ROAccess(mdbx::env&& env) : env_{std::move(env)} {}
    ROAccess(const ROAccess&) noexcept = default;
    ROAccess(ROAccess&&) noexcept = default;

    ROTxnManaged start_ro_tx() { return ROTxnManaged(env_); }

    mdbx::env& operator*() { return env_; }

  protected:
    mdbx::env env_;
};

//! \brief This class create RWTxn(s) on demand, it is used to enforce in some method signatures the type of db access
class RWAccess : public ROAccess {
  public:
    explicit RWAccess(const mdbx::env& env) : ROAccess{env} {}
    explicit RWAccess(mdbx::env&& env) : ROAccess{std::move(env)} {}
    RWAccess(const RWAccess&) noexcept = default;
    RWAccess(RWAccess&&) noexcept = default;

    RWTxnManaged start_rw_tx() { return RWTxnManaged(env_); }
};

//! \brief Reference to a processing function invoked by cursor_for_each & cursor_for_count on each record
using WalkFuncRef = absl::FunctionRef<void(ByteView key, ByteView value)>;

//! \brief Essential environment settings
struct EnvConfig {
    std::string path{};
    bool create{false};                 // Whether db file must be created
    bool readonly{false};               // Whether db should be opened in RO mode
    bool exclusive{false};              // Whether this process has exclusive access
    bool in_memory{false};              // Whether this db is in memory
    bool shared{false};                 // Whether this process opens a db already opened by another process
    bool read_ahead{false};             // Whether to enable mdbx read ahead
    bool write_map{false};              // Whether to enable mdbx write map
    size_t page_size{os::page_size()};  // Mdbx page size
    size_t max_size{3_Tebi};            // Mdbx max map size
    size_t growth_size{2_Gibi};         // Increment size for each extension
    uint32_t max_tables{256};           // Default max number of named tables
    uint32_t max_readers{100};          // Default max number of readers
};

//! \brief EnvUnmanaged wraps an *unmanaged* MDBX environment, which means the underlying environment
//! lifecycle is not touched by this class.
struct EnvUnmanaged : public ::mdbx::env {
    explicit EnvUnmanaged(MDBX_env* ptr) : ::mdbx::env{ptr} {}
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

//! \brief Computes the max size of single-value data to fit into a leaf data page
//! \param [in] page_size : the actually configured MDBX page size
//! \param [in] key_size : the known key size to fit in bundle computed value size
size_t max_value_size_for_leaf_page(size_t page_size, size_t key_size);

//! \brief Computes the max size of single-value data to fit into a leaf data page
//! \param [in] txn : the transaction used to derive pagesize from
//! \param [in] key_size : the known key size to fit in bundle computed value size
size_t max_value_size_for_leaf_page(const ::mdbx::txn& txn, size_t key_size);

//! \brief Managed cursor class to access cursor API
//! \remarks Unlike ::mdbx::cursor_managed this class withdraws and deposits allocated MDBX_cursor handles in a
//! thread-local pool for reuse. This helps avoiding multiple malloc on cursor creation.
class PooledCursor : public RWCursorDupSort, protected ::mdbx::cursor {
  public:
    explicit PooledCursor();
    explicit PooledCursor(ROTxn& txn, ::mdbx::map_handle map);
    explicit PooledCursor(::mdbx::txn& txn, const MapConfig& config);
    explicit PooledCursor(ROTxn& txn, const MapConfig& config) : PooledCursor(*txn, config) {}
    ~PooledCursor() override;

    PooledCursor(PooledCursor&& other) noexcept;
    PooledCursor& operator=(PooledCursor&& other) noexcept;

    PooledCursor(const PooledCursor&) = delete;
    PooledCursor& operator=(const PooledCursor&) = delete;

    //! \brief Reuse current cursor binding it to provided transaction and map
    void bind(ROTxn& txn, ::mdbx::map_handle map);

    //! \brief Reuse current cursor binding it to provided transaction and map configuration
    void bind(::mdbx::txn& txn, const MapConfig& config);

    void bind(ROTxn& txn, const MapConfig& config) override { bind(*txn, config); }

    std::unique_ptr<ROCursor> clone() override;

    //! \brief Closes cursor causing de-allocation of MDBX_cursor handle
    //! \remarks After this call the cursor is not reusable and the handle does not return to the cache
    void close();

    //! \brief Returns stat info of underlying dbi
    MDBX_stat get_map_stat() const;

    //! \brief Returns flags of underlying dbi
    MDBX_db_flags_t get_map_flags() const;

    //! \brief Returns the size of the underlying table
    size_t size() const override;

    using ::mdbx::cursor::operator bool;

    bool is_multi_value() const override;

    bool is_dangling() const override;

    ::mdbx::map_handle map() const override;

    CursorResult to_first() override;
    CursorResult to_first(bool throw_notfound) override;
    CursorResult to_previous() override;
    CursorResult to_previous(bool throw_notfound) override;
    CursorResult current() const override;
    CursorResult current(bool throw_notfound) const override;
    CursorResult to_next() override;
    CursorResult to_next(bool throw_notfound) override;
    CursorResult to_last() override;
    CursorResult to_last(bool throw_notfound) override;
    CursorResult find(const Slice& key) override;
    CursorResult find(const Slice& key, bool throw_notfound) override;
    CursorResult lower_bound(const Slice& key) override;
    CursorResult lower_bound(const Slice& key, bool throw_notfound) override;
    MoveResult move(MoveOperation operation, bool throw_notfound) override;
    MoveResult move(MoveOperation operation, const Slice& key, bool throw_notfound) override;
    bool seek(const Slice& key) override;
    bool eof() const override;
    bool on_first() const override;
    bool on_last() const override;
    CursorResult to_previous_last_multi() override;
    CursorResult to_previous_last_multi(bool throw_notfound) override;
    CursorResult to_current_first_multi() override;
    CursorResult to_current_first_multi(bool throw_notfound) override;
    CursorResult to_current_prev_multi() override;
    CursorResult to_current_prev_multi(bool throw_notfound) override;
    CursorResult to_current_next_multi() override;
    CursorResult to_current_next_multi(bool throw_notfound) override;
    CursorResult to_current_last_multi() override;
    CursorResult to_current_last_multi(bool throw_notfound) override;
    CursorResult to_next_first_multi() override;
    CursorResult to_next_first_multi(bool throw_notfound) override;
    CursorResult find_multivalue(const Slice& key, const Slice& value) override;
    CursorResult find_multivalue(const Slice& key, const Slice& value, bool throw_notfound) override;
    CursorResult lower_bound_multivalue(const Slice& key, const Slice& value) override;
    CursorResult lower_bound_multivalue(const Slice& key, const Slice& value, bool throw_notfound) override;
    MoveResult move(MoveOperation operation, const Slice& key, const Slice& value, bool throw_notfound) override;
    size_t count_multivalue() const override;
    MDBX_error_t put(const Slice& key, Slice* value, MDBX_put_flags_t flags) noexcept override;
    void insert(const Slice& key, Slice value) override;
    void upsert(const Slice& key, const Slice& value) override;
    void update(const Slice& key, const Slice& value) override;
    void append(const Slice& key, const Slice& value) override;
    bool erase() override;
    bool erase(bool whole_multivalue) override;
    bool erase(const Slice& key) override;
    bool erase(const Slice& key, bool whole_multivalue) override;
    bool erase(const Slice& key, const Slice& value) override;

    //! \brief Exposes handles cache
    static const ObjectPool<MDBX_cursor, detail::CursorHandleDeleter>& handles_cache() { return handles_pool_; }

  private:
    static thread_local ObjectPool<MDBX_cursor, detail::CursorHandleDeleter> handles_pool_;
};

//! \brief Checks whether a provided map name exists in database
//! \param [in] tx : a reference to a valid mdbx transaction
//! \param [in] map_name : the name of the map to check for
//! \return True / False
bool has_map(::mdbx::txn& tx, const char* map_name);

//! \brief List the names of the existing maps in database
//! \param [in] tx : a reference to a valid mdbx transaction
//! \return the sequence of map names
std::vector<std::string> list_maps(::mdbx::txn& tx, bool throw_notfound = false);

//! \brief Builds the full path to mdbx datafile provided a directory
//! \param [in] base_path : a reference to the directory holding the data file
//! \return A path with file name
inline std::filesystem::path get_datafile_path(const std::filesystem::path& base_path) noexcept {
    return std::filesystem::path(base_path / std::filesystem::path(kDbDataFileName));
}

//! \brief Defines the direction of cursor while looping by cursor_for_each or cursor_for_count
enum class CursorMoveDirection : uint8_t {
    kForward,
    kReverse
};

//! \brief Executes a function on each record reachable by the provided cursor
//! \param [in] cursor : A reference to a cursor opened on a map
//! \param [in] walker : A reference to a function with the code to execute on records. Note the return value of the
//! function may stop the loop
//! \param [in] direction : Whether the cursor should navigate records forward (default) or backwards
//! \return The overall number of processed records
//! \remarks If the provided cursor is *not* positioned on any record it will be moved to either the beginning or the
//! end of the table on behalf of the move criteria
size_t cursor_for_each(ROCursor& cursor, WalkFuncRef walker,
                       CursorMoveDirection direction = CursorMoveDirection::kForward);

//! \brief Executes a function on each record reachable by the provided cursor asserting keys start with provided prefix
//! \param [in] cursor : A reference to a cursor opened on a map
//! \param [in] prefix : The prefix each key must start with
//! \param [in] walker : A reference to a function with the code to execute on records. Note the return value of the
//! function may stop the loop
//! \param [in] direction : Whether the cursor should navigate records forward (default) or backwards
//! \return The overall number of processed records
size_t cursor_for_prefix(ROCursor& cursor, ByteView prefix, WalkFuncRef walker,
                         CursorMoveDirection direction = CursorMoveDirection::kForward);

//! \brief Executes a function on each record reachable by the provided cursor up to a max number of iterations
//! \param [in] cursor : A reference to a cursor opened on a map
//! \param [in] walker : A reference to a function with the code to execute on records. Note the return value of the
//! function may stop the loop
//! \param [in] max_count : Max number of iterations
//! \param [in] direction : Whether the cursor should navigate records forward (default) or backwards
//! \return The overall number of processed records. Should it not match the value of max_count it means the cursor has
//! reached either the end or the beginning of table earlier
//! \remarks If the provided cursor is *not* positioned on any record it will be moved to either the beginning or the
//! end of the table on behalf of the move criteria
size_t cursor_for_count(ROCursor& cursor, WalkFuncRef walker, size_t max_count,
                        CursorMoveDirection direction = CursorMoveDirection::kForward);

//! \brief Erases map records by cursor until any record is found
//! \param [in] cursor : A reference to a cursor opened on a map
//! \param [in] set_key : The key where to set the cursor to.
//! \param [in] direction : Whether the cursor should navigate records forward (default) or backwards.
//! \return The overall number of erased records
//! \remarks When direction is forward all keys greater equal set_key will be deleted. When direction is reverse all
//! keys lower than set_key will be deleted.
size_t cursor_erase(RWCursor& cursor, ByteView set_key,
                    CursorMoveDirection direction = CursorMoveDirection::kForward);

//! \brief Erases all records whose key starts with a prefix
//! \param [in] cursor : A reference to a cursor opened on a map
//! \param [in] prefix : Delete keys starting with this prefix
size_t cursor_erase_prefix(RWCursor& cursor, ByteView prefix);

inline Slice to_slice(ByteView value) {
    return {value.data(), value.length()};
}

inline ByteView from_slice(const Slice slice) {
    return {static_cast<const uint8_t*>(slice.data()), slice.length()};
}

}  // namespace silkworm::datastore::kvdb
