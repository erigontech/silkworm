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

#include "util.hpp"

namespace silkworm::lmdb {

Environment::Environment(const unsigned flags) {
    int ret{err_handler(mdb_env_create(&handle_))};
    if (flags) {
        ret = mdb_env_set_flags(handle_, flags, 1);
        if (ret != MDB_SUCCESS) {
            close();
            throw exception(ret, mdb_strerror(ret));
        }
    }
}
Environment::~Environment() noexcept { close(); }

bool Environment::is_ro(void) {
    unsigned int env_flags{0};
    int rc{get_flags(&env_flags)};
    if (!rc) {
        return ((env_flags & MDB_RDONLY) == MDB_RDONLY);
    }
    throw exception(rc, mdb_strerror(rc));
}

void Environment::open(const char* path, const unsigned int flags, const mdb_mode_t mode) {
    assert_handle();
    if (!path) {
        throw std::invalid_argument("Invalid argument : path");
    }
    (void)err_handler(mdb_env_open(handle_, path, flags, mode));
    opened_ = true;  // If we get here the above has not thrown so the open is successful
}

void Environment::close() noexcept {
    if (assert_opened(false)) {
        signal_on_before_close_();
        mdb_env_close(handle_);
        handle_ = nullptr;
        opened_ = false;
    }
}

int Environment::get_info(MDB_envinfo* info) {
    assert_opened();
    if (!info) {
        throw std::invalid_argument("Invalid argument : info");
    }
    return mdb_env_info(handle_, info);
}

int Environment::get_flags(unsigned int* flags) {
    assert_handle();
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

int Environment::get_max_keysize(void) {
    assert_opened();
    return mdb_env_get_maxkeysize(handle_);
}

int Environment::get_max_readers(unsigned int* count) {
    assert_handle();
    if (!count) {
        throw std::invalid_argument("Invalid argument : count");
    }
    return mdb_env_get_maxreaders(handle_, count);
}

int Environment::set_flags(const unsigned int flags, const bool onoff) {
    assert_handle();
    return mdb_env_set_flags(handle_, flags, onoff ? 1 : 0);
}

int Environment::set_mapsize(const size_t size) {
    assert_handle();
    return mdb_env_set_mapsize(handle_, size);
}

int Environment::set_max_dbs(const unsigned int count) {
    /*
     * May be invoked only after env create
     * and BEFORE env open
     */
    assert_handle();
    if (opened_) {
        throw std::runtime_error("Can't change max_dbs for an opened database");
    }
    return mdb_env_set_maxdbs(handle_, count);
}

int Environment::set_max_readers(const unsigned int count) {
    assert_handle();
    return mdb_env_set_maxreaders(handle_, count);
}

int Environment::sync(const bool force) {
    assert_opened();
    return mdb_env_sync(handle_, force);
}

int Environment::get_ro_txns(void) { return ro_txns_[std::this_thread::get_id()]; }
int Environment::get_rw_txns(void) { return rw_txns_[std::this_thread::get_id()]; }

void Environment::touch_ro_txns(int count) {
    std::lock_guard<std::mutex> l(count_mtx_);
    ro_txns_[std::this_thread::get_id()] += count;
}

void Environment::touch_rw_txns(int count) {
    std::lock_guard<std::mutex> l(count_mtx_);
    rw_txns_[std::this_thread::get_id()] += count;
}

bool Environment::assert_handle(bool should_throw) {
    bool retvar{handle_ != nullptr};
    if (!retvar && should_throw) {
        throw std::runtime_error("Invalid or closed lmdb environment");
    }
    return retvar;
}

bool Environment::assert_opened(bool should_throw) {
    bool ret{assert_handle(should_throw)};
    if (!ret) return ret;
    if (!opened_ && should_throw) {
        throw std::runtime_error("Closed lmdb environment");
    }
    return opened_;
}

std::unique_ptr<Transaction> Environment::begin_transaction(unsigned int flags) {
    assert_opened();
    if (is_ro()) {
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
    : parent_env_{parent},
      handle_{txn},
      flags_{flags},
      conn_on_env_close_{parent->signal_on_before_close_.connect(boost::bind(&Transaction::abort, this))} {}

bool Transaction::assert_handle(bool should_throw) {
    bool retvar{handle_ != nullptr};
    if (!retvar && should_throw) {
        throw std::runtime_error("Commited/Aborted lmdb transaction");
    }
    return retvar;
}

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
    (void)parent_env->get_flags(&env_flags);

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
            (void)parent_env->set_mapsize(0);
        } else if (rc == MDB_SUCCESS) {
            if (txn_ro) {
                parent_env->touch_ro_txns(1);
            } else {
                parent_env->touch_rw_txns(1);
            }
            break;
        }
    } while (--maxtries > 0);

    if (rc) {
        throw lmdb::exception(rc, mdb_strerror(rc));
    }
    return retvar;
}

std::optional<std::pair<std::string, MDB_dbi>> Transaction::open_dbi(const char* name, unsigned int flags) {
    std::string namestr{};
    if (name) {
        namestr.assign(name);
    }
    return open_dbi(namestr, flags);
}

std::optional<std::pair<std::string, MDB_dbi>> Transaction::open_dbi(const std::string name, unsigned int flags) {
    assert_handle();

    // Lookup value in map
    auto iter = dbis_.find(name);
    if (iter != dbis_.end()) {
        return {std::pair(iter->first, iter->second)};
    }

    // TODO(Andrea)
    // Every bucket has its own set of flags
    // Lookup somewhere how to configure a bucket
    MDB_dbi newdbi{0};

    int rc{mdb_dbi_open(handle_, (name.empty() ? 0 : name.c_str()), flags, &newdbi)};
    if (rc != MDB_SUCCESS) {
        return {};
    }
    dbis_[name] = newdbi;
    return {std::pair(name, newdbi)};
}

Transaction::Transaction(Environment* parent, unsigned int flags)
    : Transaction(parent, open_transaction(parent, nullptr, flags), flags) {}
Transaction::~Transaction() { abort(); }

bool Transaction::is_ro(void) { return ((flags_ & MDB_RDONLY) == MDB_RDONLY); }

std::unique_ptr<Table> Transaction::open(const char* name, unsigned int flags) {
    std::optional<std::pair<std::string, MDB_dbi>> dbi{open_dbi(name, flags)};
    if (!dbi) {
        throw exception(MDB_NOTFOUND, mdb_strerror(MDB_NOTFOUND));
    }
    return std::make_unique<Table>(this, dbi.value().second, dbi.value().first);
}

void Transaction::abort(void) {
    if (!assert_handle(false)) {
        return;
    }
    signal_on_before_abort_();  // Signals connected buckets to close
    mdb_txn_abort(handle_);
    if (is_ro()) {
        parent_env_->touch_ro_txns(-1);
    } else {
        parent_env_->touch_rw_txns(-1);
    }
    conn_on_env_close_.disconnect();  // Disconnects from parent env events
    handle_ = nullptr;
}

int Transaction::commit(void) {
    assert_handle();
    signal_on_before_commit_();  // Signals connected buckets to close
    int rc{mdb_txn_commit(handle_)};
    if (rc == MDB_SUCCESS) {
        if (is_ro()) {
            parent_env_->touch_ro_txns(-1);
        } else {
            parent_env_->touch_rw_txns(-1);
        }
        conn_on_env_close_.disconnect();  // Disconnects from parent env events
        handle_ = nullptr;
    }
    return rc;
}

/*
 * Buckets
 */

Table::Table(Transaction* parent, MDB_dbi dbi, std::string dbi_name)
    : Table::Table(parent, dbi, dbi_name, open_cursor(parent, dbi)) {}

Table::~Table() { close(); }

MDB_cursor* Table::open_cursor(Transaction* parent, MDB_dbi dbi) {
    if (!*parent->handle()) {
        throw std::runtime_error("Database or transaction closed");
    }
    MDB_cursor* retvar{nullptr};
    (void)err_handler(mdb_cursor_open(*parent->handle(), dbi, &retvar));
    return retvar;
}

Table::Table(Transaction* parent, MDB_dbi dbi, std::string dbi_name, MDB_cursor* cursor)
    : parent_txn_{parent},
      dbi_{dbi},
      dbi_name_{std::move(dbi_name)},
      handle_{cursor},
      conn_on_txn_abort_{parent->signal_on_before_abort_.connect(boost::bind(&Table::close, this))},
      conn_on_txn_commit_{parent->signal_on_before_commit_.connect(boost::bind(&Table::close, this))} {}

int Table::get_flags(unsigned int* flags) { return mdb_dbi_flags(*parent_txn_->handle(), dbi_, flags); }

int Table::get_stat(MDB_stat* stat) { return mdb_stat(*parent_txn_->handle(), dbi_, stat); }

int Table::get_rcount(size_t* count) {
    MDB_stat stat{};
    int rc{get_stat(&stat)};
    if (!rc) *count = stat.ms_entries;
    return rc;
}

std::string Table::get_name(void) { return dbi_name_; }

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
    assert_handle();
    return mdb_cursor_get(handle_, key, data, operation);
}

int Table::put(MDB_val* key, MDB_val* data, unsigned int flag) {
    assert_handle();
    return mdb_cursor_put(handle_, key, data, flag);
}

bool Table::assert_handle(bool should_throw) {
    bool retvar{handle_ != nullptr};
    if (!retvar && should_throw) {
        throw std::runtime_error("Invalid or closed cursor for bucket " +
                                 (dbi_name_.empty() ? "[unnamed]" : dbi_name_));
    }
    return retvar;
}

std::optional<ByteView> Table::get(ByteView key) {
    MDB_val key_val{db::to_mdb_val(key)};
    MDB_val data;
    int rc{get(&key_val, &data, MDB_SET)};
    if (rc == MDB_NOTFOUND) {
        return {};
    }
    (void)err_handler(rc);
    return db::from_mdb_val(data);
}

int Table::seek(MDB_val* key, MDB_val* data) { return get(key, data, MDB_SET_RANGE); }
int Table::seek_exact(MDB_val* key, MDB_val* data) { return get(key, data, MDB_SET); }
int Table::get_current(MDB_val* key, MDB_val* data) { return get(key, data, MDB_GET_CURRENT); }
int Table::del_current(bool dupdata) { return mdb_cursor_del(handle_, (dupdata ? MDB_NODUPDATA : 0u)); }
int Table::get_first(MDB_val* key, MDB_val* data) { return get(key, data, MDB_FIRST); }
int Table::get_prev(MDB_val* key, MDB_val* data) { return get(key, data, MDB_PREV); }
int Table::get_next(MDB_val* key, MDB_val* data) { return get(key, data, MDB_NEXT); }
int Table::get_last(MDB_val* key, MDB_val* data) { return get(key, data, MDB_LAST); }
int Table::get_dcount(size_t* count) { return mdb_cursor_count(handle_, count); }

int Table::put(MDB_val* key, MDB_val* data) { return put(key, data, 0u); }
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
    if (assert_handle(false)) {
        conn_on_txn_abort_.disconnect();  // Disconnects from parent Transaction events
        conn_on_txn_commit_.disconnect();
        mdb_cursor_close(handle_);
        handle_ = nullptr;
    }
}

std::shared_ptr<lmdb::Environment> get_env(const char* path, lmdb::options opts, bool forwriting) {
    struct Value {
        std::weak_ptr<lmdb::Environment> wp;
        unsigned int flags;
    };

    static std::map<size_t, Value> s_envs;
    static std::mutex s_mtx;

    // Compute flags for required instance
    unsigned int flags{0};
    if (opts.no_tls) flags |= MDB_NOTLS;
    if (opts.no_rdahead) flags |= MDB_NORDAHEAD;
    if (opts.no_sync) flags |= MDB_NOSYNC;
    if (opts.no_sync) flags |= MDB_NOSYNC;
    if (opts.no_meta_sync) flags |= MDB_NOMETASYNC;
    if (opts.write_map) flags |= MDB_WRITEMAP;
    if (opts.no_sub_dir) flags |= MDB_NOSUBDIR;

    // There's a 1:1 relation among env and the opened
    // database file. Build a hash of the path
    std::string pathstr{path};
    std::hash<std::string> pathhash;
    size_t envkey{pathhash(pathstr)};

    // Only one thread at a time
    std::lock_guard<std::mutex> l(s_mtx);

    // Locate env if already exists
    auto iter = s_envs.find(envkey);
    if (iter != s_envs.end()) {
        if (iter->second.flags != flags) {
            throw lmdb::exception(MDB_INCOMPATIBLE, mdb_strerror(MDB_INCOMPATIBLE));
        }
        auto item = iter->second.wp.lock();
        if (item && item->is_opened()) {
            return item;
        } else {
            s_envs.erase(iter);
        }
    }

    // Create new instance and open db file(s)
    auto newitem = std::make_shared<lmdb::Environment>();
    (void)newitem->set_mapsize(opts.map_size);
    (void)newitem->set_max_dbs(opts.max_buckets);
    newitem->open(path, flags | (forwriting ? 0 : MDB_RDONLY), opts.mode);  // Throws on error

    s_envs[envkey] = {newitem, flags};
    return newitem;
}

}  // namespace silkworm::lmdb
