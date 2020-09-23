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

namespace silkworm::db {

    namespace lmdb {
        /*
         * Environment
         */

        Env::Env(const unsigned flags) {
            int ret{err_handler(mdb_env_create(&handle_), true)};
            if (flags) {
                ret = err_handler(mdb_env_set_flags(handle_, flags, 1));
                if (ret) {
                    close();
                    throw exception(ret, mdb_strerror(ret));
                }
            }
        }
        Env::~Env() noexcept { close(); }

        bool Env::is_ro(void) {
            if (!handle_) return false;
            unsigned int env_flags{0};
            get_flags(&env_flags);
            return (env_flags & MDB_RDONLY) == MDB_RDONLY;
        }

        void Env::open(const char* path, const unsigned int flags, const mdb_mode_t mode) {
            if (opened_) return;
            (void)err_handler(mdb_env_open(handle_, path, flags, mode), true);
            opened_ = true;
        }

        void Env::close() noexcept {
            if (handle_) {
                mdb_env_close(handle_);
                handle_ = nullptr;
                opened_ = false;
            }
        }

        int Env::get_flags(unsigned int* flags) { return err_handler(mdb_env_get_flags(handle_, flags)); }

        int Env::get_max_keysize(void) {
            if (!handle_) return 0;
            return mdb_env_get_maxkeysize(handle_);
        }

        int Env::get_max_readers(unsigned int* count) { return err_handler(mdb_env_get_maxreaders(handle_, count)); }

        int Env::set_flags(const unsigned int flags, const bool onoff) {
            return err_handler(mdb_env_set_flags(handle_, flags, onoff ? 1 : 0));
        }

        int Env::set_mapsize(const size_t size) { return err_handler(mdb_env_set_mapsize(handle_, size)); }

        int Env::set_max_dbs(const unsigned int count) { return err_handler(mdb_env_set_maxdbs(handle_, count)); }

        int Env::set_max_readers(const unsigned int count) {
            return err_handler(mdb_env_set_maxreaders(handle_, count));
        }

        int Env::sync(const bool force) { return err_handler(mdb_env_sync(handle_, force)); }

        int Env::get_ro_txns(void) { return ro_txns_[std::this_thread::get_id()]; }
        int Env::get_rw_txns(void) { return rw_txns_[std::this_thread::get_id()]; }

        void Env::touch_ro_txns(int count) {
            std::lock_guard<std::mutex> l(count_mtx_);
            ro_txns_[std::this_thread::get_id()] += count;
        }
        void Env::touch_rw_txns(int count) {
            std::lock_guard<std::mutex> l(count_mtx_);
            rw_txns_[std::this_thread::get_id()] += count;
        }

        std::unique_ptr<Txn> Env::begin_transaction(unsigned int flags) { return std::make_unique<Txn>(this, flags); }
        std::unique_ptr<Txn> Env::begin_ro_transaction(unsigned int flags) {
            // Simple overload to ensure MDB_RDONLY is set
            flags |= MDB_RDONLY;
            return begin_transaction(flags);
        }
        std::unique_ptr<Txn> Env::begin_rw_transaction(unsigned int flags) {
            // Simple overload to ensure MDB_RDONLY is not set
            flags &= ~MDB_RDONLY;
            return begin_transaction(flags);
        }

        /*
         * Transactions
         */

        Txn::Txn(Env* parent, MDB_txn* txn, unsigned int flags) : parent_env_{parent}, handle_{txn}, flags_{flags} {}

        void Txn::set_dirty(void) { dirty_ = true; }

        MDB_txn* Txn::open_transaction(Env* parent_env, MDB_txn* parent_txn, unsigned int flags) {
            if (!parent_env->is_opened()) {
                throw std::runtime_error("Can't open a transaction on a closed db");
            }

            /*
             * A transaction and its cursors must only be used by a single thread,
             * and a thread may only have one transaction at a time.
             * If MDB_NOTLS is in use this does not apply to read-only transactions
             */

            if (parent_env->get_rw_txns()) {
                throw std::runtime_error("Rw transaction already pending in this thread");
            }

            // Verify we don't open a rw tx in a ro env
            unsigned int env_flags{0};
            (void)parent_env->get_flags(&env_flags);

            bool env_ro{(env_flags & MDB_RDONLY) == MDB_RDONLY};
            bool txn_ro{(flags & MDB_RDONLY) == MDB_RDONLY};

            if (env_ro && !txn_ro) {
                throw std::runtime_error("Can't open a rw transaction on a ro env");
            }

            bool env_notls{(env_flags & MDB_NOTLS) == MDB_NOTLS};
            if (txn_ro && !env_notls) {
                if (parent_env->get_ro_txns()) {
                    throw std::runtime_error("Ro transaction already pending in this thread");
                }
            }

            MDB_txn* retvar{nullptr};
            int maxtries{3};
            int rc{0};

            do {
                rc = err_handler(mdb_txn_begin(*(parent_env->handle()), parent_txn, flags, &retvar));
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

        std::optional<std::pair<std::string, MDB_dbi>> Txn::open_dbi(const char* name, unsigned int flags) {
            std::string namestr{};
            if (name) {
                namestr.assign(name);
            }
            return open_dbi(namestr, flags);
        }

        std::optional<std::pair<std::string, MDB_dbi>> Txn::open_dbi(const std::string name, unsigned int flags) {
            // Lookup value in map
            auto iter = dbis_.find(name);
            if (iter != dbis_.end()) {
                return {std::pair(iter->first, iter->second)};
            }

            // TODO(Andrea)
            // Every bucket has its own set of flags
            // Lookup somewhere how to configure a bucket
            MDB_dbi newdbi{0};

            // Allow execption to throw when opening
            int rc{err_handler(mdb_dbi_open(handle_, (name.empty() ? 0 : name.c_str()), flags, &newdbi))};
            if (rc) return {};

            dbis_[name] = newdbi;
            return {std::pair(name, newdbi)};
        }

        Txn::Txn(Env* parent, unsigned int flags) : Txn(parent, open_transaction(parent, nullptr, flags), flags) {}
        Txn::~Txn() {
            // TODO(Andrea)
            /* Call to destructor if txn is pending may cause
             * unpredictable results as it requires to access
             * parent env and decrement the number of opened txns
             * if parent_env has already been voided (eg. program termination)
             * this causes a segfault
             */
            abort();
        }

        bool Txn::is_ro(void) { return ((flags_ & MDB_RDONLY) == MDB_RDONLY); }

        bool Txn::is_dirty(void) { return is_ro() ? false : dirty_; }

        std::unique_ptr<Bkt> Txn::open(const char* name, unsigned int flags) {
            std::optional<std::pair<std::string, MDB_dbi>> dbi{open_dbi(name, flags)};
            if (!dbi) {
                throw exception(MDB_NOTFOUND, mdb_strerror(MDB_NOTFOUND));
            }
            return std::make_unique<Bkt>(this, dbi.value().second, dbi.value().first);
        }

        void Txn::abort(void) {
            if (!handle_) return;
            signal_on_before_abort();
            mdb_txn_abort(handle_);
            if (is_ro()) {
                parent_env_->touch_ro_txns(-1);
            } else {
                parent_env_->touch_rw_txns(-1);
            }
            handle_ = nullptr;
            dirty_ = false;
        }

        int Txn::commit(void) {
            if (!handle_) return 0;
            signal_on_before_commit();
            int rc{err_handler(mdb_txn_commit(handle_))};
            if (rc == MDB_SUCCESS) {
                if (is_ro()) {
                    parent_env_->touch_ro_txns(-1);
                } else {
                    parent_env_->touch_rw_txns(-1);
                }
                handle_ = nullptr;
                dirty_ = false;
            }
            return rc;
        }

        /*
         * Buckets
         */

        Bkt::Bkt(Txn* parent, MDB_dbi dbi, std::string dbi_name)
            : Bkt::Bkt(parent, dbi, dbi_name, open_cursor(parent, dbi)) {}

        Bkt::~Bkt() { close(); }

        MDB_cursor* Bkt::open_cursor(Txn* parent, MDB_dbi dbi) {
            if (!*parent->handle()) {
                throw std::runtime_error("Database or transaction closed");
            }
            MDB_cursor* retvar{nullptr};
            (void)err_handler(mdb_cursor_open(*parent->handle(), dbi, &retvar), true);
            return retvar;
        }

        Bkt::Bkt(Txn* parent, MDB_dbi dbi, std::string dbi_name, MDB_cursor* cursor)
            : parent_txn_{parent}, dbi_{dbi}, dbi_name_{std::move(dbi_name)}, cursor_{cursor} {
            parent->signal_on_before_abort.connect(boost::bind(&Bkt::close, this));
            parent->signal_on_before_commit.connect(boost::bind(&Bkt::close, this));
        }

        int Bkt::get_flags(unsigned int* flags) {
            return err_handler(mdb_dbi_flags(*parent_txn_->handle(), dbi_, flags));
        }

        int Bkt::get_stat(MDB_stat* stat) { return err_handler(mdb_stat(*parent_txn_->handle(), dbi_, stat)); }

        int Bkt::get_rcount(size_t* count) {
            MDB_stat stat{};
            int rc{get_stat(&stat)};
            if (!rc) *count = stat.ms_entries;
            return rc;
        }

        int Bkt::get(MDB_val* key, MDB_val* data, MDB_cursor_op operation) {
            if (!cursor_) {
                throw exception(EINVAL, mdb_strerror(EINVAL));
            }
            int rc{err_handler(mdb_cursor_get(cursor_, key, data, operation))};
            return rc;
        }

        int Bkt::put(MDB_val* key, MDB_val* data, unsigned int flag) {
            if (parent_txn_->is_ro()) {
                throw std::runtime_error("Can't put within a ro Transaction");
            }
            if (!cursor_) {
                throw exception(EINVAL, mdb_strerror(EINVAL));
            }
            int rc{err_handler(mdb_cursor_put(cursor_, key, data, flag))};
            if (!rc) {
                parent_txn_->set_dirty();
            }
            return rc;
        }

        int Bkt::seek(MDB_val* key, MDB_val* data) { return get(key, data, MDB_SET_RANGE); }
        int Bkt::seek_exact(MDB_val* key, MDB_val* data) { return get(key, data, MDB_SET); }
        int Bkt::get_current(MDB_val* key, MDB_val* data) { return get(key, data, MDB_GET_CURRENT); }
        int Bkt::del_current(bool dupdata) {
            return err_handler(mdb_cursor_del(cursor_, (dupdata ? MDB_NODUPDATA : 0u)));
        }
        int Bkt::get_first(MDB_val* key, MDB_val* data) { return get(key, data, MDB_FIRST); }
        int Bkt::get_prev(MDB_val* key, MDB_val* data) { return get(key, data, MDB_PREV); }
        int Bkt::get_next(MDB_val* key, MDB_val* data) { return get(key, data, MDB_NEXT); }
        int Bkt::get_last(MDB_val* key, MDB_val* data) { return get(key, data, MDB_LAST); }
        int Bkt::get_dcount(size_t* count) { return err_handler(mdb_cursor_count(cursor_, count)); }

        int Bkt::put(MDB_val* key, MDB_val* data) { return put(key, data, 0u); }
        int Bkt::put_current(MDB_val* key, MDB_val* data) { return put(key, data, MDB_CURRENT); }
        int Bkt::put_nodup(MDB_val* key, MDB_val* data) { return put(key, data, MDB_NODUPDATA); }
        int Bkt::put_noovrw(MDB_val* key, MDB_val* data) { return put(key, data, MDB_NOOVERWRITE); }
        int Bkt::put_reserve(MDB_val* key, MDB_val* data) { return put(key, data, MDB_RESERVE); }
        int Bkt::put_append(MDB_val* key, MDB_val* data) { return put(key, data, MDB_APPEND); }
        int Bkt::put_append_dup(MDB_val* key, MDB_val* data) { return put(key, data, MDB_APPENDDUP); }
        int Bkt::put_multiple(MDB_val* key, MDB_val* data) { return put(key, data, MDB_MULTIPLE); }

        void Bkt::close() {

            // Free the cursor handle
            // There is no need to close the dbi_ handle
            if (!cursor_) return;
            mdb_cursor_close(cursor_);
            cursor_ = nullptr;
        }


    }  // namespace lmdb

    std::shared_ptr<lmdb::Env> get_env(const char* path, lmdb::options opts, bool forwriting) {
        struct Value {
            std::weak_ptr<lmdb::Env> wp;
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
        auto newitem = std::make_shared<lmdb::Env>();
        (void)newitem->set_mapsize(opts.map_size);
        (void)newitem->set_max_dbs(opts.max_buckets);
        newitem->open(path, flags | (forwriting ? 0 : MDB_RDONLY), opts.mode);  // Throws on error

        s_envs[envkey] = {newitem, flags};
        return newitem;
    }

}  // namespace silkworm::db
