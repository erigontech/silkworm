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

#include "chaindb.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/interprocess/mapped_region.hpp>

namespace silkworm::lmdb {

void DatabaseConfig::set_readonly(bool value) {
    if (value) {
        flags |= MDB_RDONLY;
    } else {
        flags &= ~MDB_RDONLY;
    }
}

Environment::Environment(const DatabaseConfig& config) {

    if (config.path.empty()) {
        throw std::invalid_argument("Invalid argument : config.path");
    }

    // Check data file exists and get its size
    // If it exists then map_size can only be either:
    // 0 - map_size is adjusted by LMDB to effective data size
    // any value >= data file size
    // *WARNING* setting a map_size != 0 && < data_size causes
    // LMDB to truncate data file thus losing data
    size_t data_file_size{0};
    size_t data_map_size{0};
    boost::filesystem::path data_path{config.path};
    bool nosubdir{ (config.flags & MDB_NOSUBDIR) == MDB_NOSUBDIR };
    if (!nosubdir) {
        data_path /= boost::filesystem::path{"data.mdb"};
    }
    if (boost::filesystem::exists(data_path)) {
        if (!boost::filesystem::is_regular_file(data_path)) {
            throw std::runtime_error(data_path.string() + " is not a regular file");
        }
        data_file_size = boost::filesystem::file_size(data_path);
    }
    data_map_size = std::max(data_file_size, config.map_size);

    // Ensure map_size is multiple of host page_size
    if (data_map_size) {
        size_t host_page_size{boost::interprocess::mapped_region::get_page_size()};
        data_map_size = ((data_map_size + host_page_size - 1) / host_page_size) * host_page_size;
    }

    err_handler(mdb_env_create(&handle_));
    err_handler(mdb_env_set_mapsize(handle_, data_map_size));
    err_handler(mdb_env_set_maxdbs(handle_, config.max_tables));

    // Eventually open data file (this may throw)
    path_ = (nosubdir ? data_path.string() : data_path.parent_path().string());
    err_handler(mdb_env_open(handle_, path_.c_str(), config.flags, config.mode));
}

Environment::~Environment() noexcept { close(); }

bool Environment::is_ro(void) {
    unsigned int env_flags{0};
    err_handler(get_flags(&env_flags));
    return ((env_flags & MDB_RDONLY) == MDB_RDONLY);
}

void Environment::close() noexcept {
    if (handle_) {
        mdb_env_close(handle_);
        handle_ = nullptr;
    }
}

int Environment::get_info(MDB_envinfo* info) {
    if (!info) {
        throw std::invalid_argument("Invalid argument : info");
    }
    return mdb_env_info(handle_, info);
}

int Environment::get_flags(unsigned int* flags) {
    if (!flags) {
        throw std::invalid_argument("Invalid argument : flags");
    }
    return mdb_env_get_flags(handle_, flags);
}

int Environment::get_mapsize(size_t* size) {
    MDB_envinfo info{};
    int rc{get_info(&info)};
    if (!rc) {
        *size = info.me_mapsize;
    }
    return rc;
}

int Environment::get_filesize(size_t* size)
{
    if (!path_.size()) return ENOENT;

    uint32_t flags{0};
    int rc{get_flags(&flags)};
    if (rc) return rc;
    boost::filesystem::path data_path{path_};
    bool nosubdir{(flags & MDB_NOSUBDIR) == MDB_NOSUBDIR};
    if (!nosubdir) data_path /= boost::filesystem::path{"data.mdb"};
    if (boost::filesystem::exists(data_path) && boost::filesystem::is_regular_file(data_path)) {
        *size = boost::filesystem::file_size(data_path);
        return MDB_SUCCESS;
    }
    return ENOENT;
}

int Environment::get_max_keysize(void) { return mdb_env_get_maxkeysize(handle_); }

int Environment::get_max_readers(unsigned int* count) {
    if (!count) {
        throw std::invalid_argument("Invalid argument : count");
    }
    return mdb_env_get_maxreaders(handle_, count);
}

int Environment::set_flags(const unsigned int flags, const bool onoff) {
    return mdb_env_set_flags(handle_, flags, onoff ? 1 : 0);
}

int Environment::set_mapsize(size_t size) {

    /*
    * A size == 0 means LMDB will auto adjust to
    * actual data file size.
    * In all other cases prevent setting map_size
    * to a lower value as it may truncate data file
    * (observed on Windows)
    */
    if (size) {
        size_t actual_map_size{0};
        int rc{get_mapsize(&actual_map_size)};
        if (rc) return rc;
        if (size < actual_map_size) {
            throw std::runtime_error("Can't set a map_size lower than data file size.");
        }
        size_t host_page_size{ boost::interprocess::mapped_region::get_page_size() };
        size = ((size + host_page_size - 1) / host_page_size) * host_page_size;
    }
    return mdb_env_set_mapsize(handle_, size);
}

int Environment::set_max_dbs(const unsigned int count) { return mdb_env_set_maxdbs(handle_, count); }

int Environment::set_max_readers(const unsigned int count) { return mdb_env_set_maxreaders(handle_, count); }

int Environment::sync(const bool force) { return mdb_env_sync(handle_, force); }

int Environment::get_ro_txns(void) noexcept { return ro_txns_[std::this_thread::get_id()]; }
int Environment::get_rw_txns(void) noexcept { return rw_txns_[std::this_thread::get_id()]; }

void Environment::touch_ro_txns(int count) noexcept {
    std::lock_guard<std::mutex> l(count_mtx_);
    ro_txns_[std::this_thread::get_id()] += count;
}

void Environment::touch_rw_txns(int count) noexcept {
    std::lock_guard<std::mutex> l(count_mtx_);
    rw_txns_[std::this_thread::get_id()] += count;
}

std::unique_ptr<Transaction> Environment::begin_transaction(unsigned int flags) {
    if (this->is_ro()) {
        flags |= MDB_RDONLY;
    }
    return std::make_unique<Transaction>(this, flags);
}
std::unique_ptr<Transaction> Environment::begin_ro_transaction(unsigned int flags) {
    // Simple overload to ensure MDB_RDONLY is set
    flags |= MDB_RDONLY;
    return begin_transaction(flags);
}
std::unique_ptr<Transaction> Environment::begin_rw_transaction(unsigned int flags) {
    // Simple overload to ensure MDB_RDONLY is NOT set
    flags &= ~MDB_RDONLY;
    return begin_transaction(flags);
}

/*
 * Transactions
 */

Transaction::Transaction(Environment* parent, MDB_txn* txn, unsigned int flags)
    : parent_env_{parent}, handle_{txn}, flags_{flags} {}

MDB_txn* Transaction::open_transaction(Environment* parent_env, MDB_txn* parent_txn, unsigned int flags) {
    /*
     * A transaction and its cursors must only be used by a single thread,
     * and a thread may only have one transaction at a time.
     * If MDB_NOTLS is in use this does not apply to read-only transactions
     */

    if (parent_env->get_rw_txns()) {
        throw std::runtime_error("Rw transaction already pending in this thread");
    }

    // Ensure we don't open a rw tx in a ro env
    unsigned int env_flags{0};
    err_handler(parent_env->get_flags(&env_flags));

    bool env_ro{(env_flags & MDB_RDONLY) == MDB_RDONLY};
    bool txn_ro{(flags & MDB_RDONLY) == MDB_RDONLY};

    if (env_ro && !txn_ro) {
        throw std::runtime_error("Can't open a RW transaction on a RO environment");
    }

    bool env_notls{(env_flags & MDB_NOTLS) == MDB_NOTLS};
    if (txn_ro && !env_notls) {
        if (parent_env->get_ro_txns()) {
            throw std::runtime_error("RO transaction already pending in this thread");
        }
    }

    MDB_txn* retvar{nullptr};
    int maxtries{3};
    int rc{0};

    do {
        rc = mdb_txn_begin(*(parent_env->handle()), parent_txn, flags, &retvar);
        if (rc == MDB_MAP_RESIZED) {
            /*
             * If mapsize is resized by another process call mdb_env_set_mapsize
             * with a size of zero to adapt to new size
             */
            err_handler(parent_env->set_mapsize(0));
        } else if (rc == MDB_SUCCESS) {
            if (txn_ro) {
                parent_env->touch_ro_txns(1);
            } else {
                parent_env->touch_rw_txns(1);
            }
            break;
        }
    } while (--maxtries > 0);
    err_handler(rc);
    return retvar;
}

MDB_dbi Transaction::open_dbi(const char* name, unsigned int flags) {
    MDB_dbi newdbi{0};
    err_handler(mdb_dbi_open(handle_, name, flags, &newdbi));
    return newdbi;
}

Transaction::Transaction(Environment* parent, unsigned int flags)
    : Transaction(parent, open_transaction(parent, nullptr, flags), flags) {}
Transaction::~Transaction() { abort(); }

size_t Transaction::get_id(void) { return mdb_txn_id(handle_); }

bool Transaction::is_ro(void) { return ((flags_ & MDB_RDONLY) == MDB_RDONLY); }

std::unique_ptr<Table> Transaction::open(const TableConfig& config, unsigned flags) {
    flags |= config.flags;
    MDB_dbi dbi{open_dbi(config.name, flags)};

    // Apply custom comparators (if any)
    // Uncomment the following when necessary
    // switch (config.key_comparator) // use mdb_set_compare
    //{
    // default:
    //    break;
    //}

    // Apply custom dup comparators (if any)
    switch (config.dup_comparator)  // use mdb_set_dupsort
    {
        case TableCustomDupComparator::ExcludeSuffix32:
            err_handler(mdb_set_dupsort(handle_, dbi, dup_cmp_exclude_suffix32));
            break;
        default:
            break;
    }

    return std::make_unique<Table>(this, dbi, config.name);
}

std::unique_ptr<Table> Transaction::open(MDB_dbi dbi) {
    if (dbi > 1) {
        throw std::invalid_argument("dbi can only be 0 or 1");
    }
    return std::make_unique<Table>(this, dbi, nullptr);
}

void Transaction::abort(void) {
    if (handle_) {
        mdb_txn_abort(handle_);
        if (is_ro()) {
            parent_env_->touch_ro_txns(-1);
        } else {
            parent_env_->touch_rw_txns(-1);
        }
        handle_ = nullptr;
    }
}

int Transaction::commit(void) {
    if (!handle_) return MDB_BAD_TXN;
    int rc{mdb_txn_commit(handle_)};
    if (rc == MDB_SUCCESS) {
        if (is_ro()) {
            parent_env_->touch_ro_txns(-1);
        } else {
            parent_env_->touch_rw_txns(-1);
        }
        handle_ = nullptr;
    }
    return rc;
}

/*
 * Tables
 */

Table::Table(Transaction* parent, MDB_dbi dbi, const char* name)
    : Table::Table(parent, dbi, name, open_cursor(parent, dbi)) {}

Table::~Table() { close(); }

MDB_cursor* Table::open_cursor(Transaction* parent, MDB_dbi dbi) {
    if (!*parent->handle()) {
        throw std::runtime_error("Database or transaction closed");
    }
    MDB_cursor* retvar{nullptr};
    err_handler(mdb_cursor_open(*parent->handle(), dbi, &retvar));
    return retvar;
}

Table::Table(Transaction* parent, MDB_dbi dbi, const char* name, MDB_cursor* cursor)
    : parent_txn_{parent}, dbi_{dbi}, name_{name ? name : ""}, handle_{cursor} {}

int Table::get_flags(unsigned int* flags) { return mdb_dbi_flags(*parent_txn_->handle(), dbi_, flags); }

int Table::get_stat(MDB_stat* stat) { return mdb_stat(*parent_txn_->handle(), dbi_, stat); }

int Table::get_rcount(size_t* count) {
    MDB_stat stat{};
    int rc{get_stat(&stat)};
    if (rc == MDB_SUCCESS) {
        *count = stat.ms_entries;
    }
    return rc;
}

std::string Table::get_name(void) {
    switch (dbi_) {
        case FREE_DBI:
            return {"[FREE_DBI]"};
        case MAIN_DBI:
            return {"[MAIN_DBI]"};
        default:
            break;
    }
    return name_;
}

MDB_dbi Table::get_dbi(void) { return dbi_; }

int Table::clear() {
    close();
    return mdb_drop(parent_txn_->handle_, dbi_, 0);
}

int Table::drop() {
    close();
    dbi_dropped_ = true;
    return mdb_drop(parent_txn_->handle_, dbi_, 1);
}

int Table::get(MDB_val* key, MDB_val* data, MDB_cursor_op operation) {
    return mdb_cursor_get(handle_, key, data, operation);
}

int Table::put(MDB_val* key, MDB_val* data, unsigned int flag) { return mdb_cursor_put(handle_, key, data, flag); }

std::optional<ByteView> Table::get(ByteView key) {
    MDB_val key_val{db::to_mdb_val(key)};
    MDB_val data;
    int rc{get(&key_val, &data, MDB_SET)};
    if (rc == MDB_NOTFOUND) {
        return {};
    }
    err_handler(rc);
    return db::from_mdb_val(data);
}

std::optional<ByteView> Table::get(ByteView key, ByteView sub_key) {
    MDB_val key_val{db::to_mdb_val(key)};
    MDB_val data{db::to_mdb_val(sub_key)};
    int rc{get(&key_val, &data, MDB_GET_BOTH_RANGE)};
    if (rc == MDB_NOTFOUND) {
        return {};
    }
    err_handler(rc);

    ByteView x{db::from_mdb_val(data)};
    if (!has_prefix(x, sub_key)) {
        return {};
    } else {
        x.remove_prefix(sub_key.length());
        return x;
    }
}

void Table::del(ByteView key) {
    if (get(key)) {
        err_handler(del_current());
    }
}

void Table::del(ByteView key, ByteView sub_key) {
    if (get(key, sub_key)) {
        err_handler(del_current());
    }
}

std::optional<db::Entry> Table::seek(ByteView prefix) {
    MDB_val key_val{db::to_mdb_val(prefix)};
    MDB_val data;
    MDB_cursor_op op{prefix.empty() ? MDB_FIRST : MDB_SET_RANGE};
    int rc{get(&key_val, &data, op)};
    if (rc == MDB_NOTFOUND) {
        return {};
    }
    err_handler(rc);

    db::Entry entry;
    entry.key = db::from_mdb_val(key_val);
    entry.value = db::from_mdb_val(data);
    return entry;
}

int Table::seek(MDB_val* key, MDB_val* data) { return get(key, data, MDB_SET_RANGE); }
int Table::seek_exact(MDB_val* key, MDB_val* data) { return get(key, data, MDB_SET); }
int Table::get_current(MDB_val* key, MDB_val* data) { return get(key, data, MDB_GET_CURRENT); }
int Table::del_current(bool alldupkeys) {
    if (alldupkeys) {
        unsigned int flags{0};
        int rc{get_flags(&flags)};
        if (rc) {
            return rc;
        }
        if ((flags & MDB_DUPSORT) != MDB_DUPSORT) {
            alldupkeys = false;
        }
    }
    return mdb_cursor_del(handle_, alldupkeys ? MDB_NODUPDATA : 0);
}
int Table::get_first(MDB_val* key, MDB_val* data) { return get(key, data, MDB_FIRST); }
int Table::get_first_dup(MDB_val* key, MDB_val* data) { return get(key, data, MDB_FIRST_DUP); }
int Table::get_prev(MDB_val* key, MDB_val* data) { return get(key, data, MDB_PREV); }
int Table::get_prev_dup(MDB_val* key, MDB_val* data) { return get(key, data, MDB_PREV_DUP); }
int Table::get_next(MDB_val* key, MDB_val* data) { return get(key, data, MDB_NEXT); }
int Table::get_next_dup(MDB_val* key, MDB_val* data) { return get(key, data, MDB_NEXT_DUP); }
int Table::get_next_nodup(MDB_val* key, MDB_val* data) { return get(key, data, MDB_NEXT_NODUP); }
int Table::get_last(MDB_val* key, MDB_val* data) { return get(key, data, MDB_LAST); }
int Table::get_dcount(size_t* count) { return mdb_cursor_count(handle_, count); }

void Table::put(ByteView key, ByteView data) {
    MDB_val key_val{db::to_mdb_val(key)};
    MDB_val data_val{db::to_mdb_val(data)};
    err_handler(put(&key_val, &data_val, 0));
}

int Table::put_current(MDB_val* key, MDB_val* data) { return put(key, data, MDB_CURRENT); }
int Table::put_nodup(MDB_val* key, MDB_val* data) { return put(key, data, MDB_NODUPDATA); }
int Table::put_noovrw(MDB_val* key, MDB_val* data) { return put(key, data, MDB_NOOVERWRITE); }
int Table::put_reserve(MDB_val* key, MDB_val* data) { return put(key, data, MDB_RESERVE); }
int Table::put_append(MDB_val* key, MDB_val* data) { return put(key, data, MDB_APPEND); }
int Table::put_append_dup(MDB_val* key, MDB_val* data) { return put(key, data, MDB_APPENDDUP); }
int Table::put_multiple(MDB_val* key, MDB_val* data) { return put(key, data, MDB_MULTIPLE); }

void Table::close() {
    // Free the cursor handle
    // There is no need to close the dbi_ handle
    if (handle_) {
        mdb_cursor_close(handle_);
        handle_ = nullptr;
    }
}

std::shared_ptr<Environment> get_env(DatabaseConfig config) {
    struct Value {
        std::weak_ptr<Environment> wp;
        uint32_t flags{0};
    };

    static std::map<size_t, Value> s_envs;
    static std::mutex s_mtx;

    // Compute flags for required instance
    // We actually don't care for MDB_RDONLY
    uint32_t compare_flags{config.flags ? (config.flags &= ~MDB_RDONLY) : 0};

    // There's a 1:1 relation among env and the opened
    // database file. Build a hash of the path.
    // Note that windows is case insensitive
    std::string pathstr{boost::algorithm::to_lower_copy(config.path)};
    std::hash<std::string> pathhash;
    size_t envkey{pathhash(pathstr)};

    // Only one thread at a time
    std::lock_guard<std::mutex> l(s_mtx);

    // Locate env if already exists
    auto iter = s_envs.find(envkey);
    if (iter != s_envs.end()) {
        if (iter->second.flags != compare_flags) {
            err_handler(MDB_INCOMPATIBLE);
        }
        auto item = iter->second.wp.lock();
        if (item && item->is_opened()) {
            return item;
        } else {
            s_envs.erase(iter);
        }
    }

    // Create new instance and open db file(s)
    // Data file is opened/created on constructor
    auto newitem = std::make_shared<Environment>(config);

    s_envs[envkey] = {newitem, compare_flags};
    return newitem;
}

int dup_cmp_exclude_suffix32(const MDB_val* a, const MDB_val* b) {
    size_t lenA{(a->mv_size >= 32) ? a->mv_size - 32 : a->mv_size};
    size_t lenB{(b->mv_size >= 32) ? b->mv_size - 32 : b->mv_size};
    size_t len{lenA};
    int64_t len_diff{(int64_t)lenA - (int64_t)(lenB)};

    if (len_diff > 0) {
        len = lenB;
        len_diff = 1;
    }
    int diff{memcmp(a->mv_data, b->mv_data, len)};
    return diff ? diff : (len_diff < 0 ? -1 : (int)len_diff);
}
}  // namespace silkworm::lmdb
