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

    namespace lmdb
    {
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

        bool Env::is_ro(void)
        {
            if (!handle_) return false;
            unsigned int env_flags{ 0 };
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

        int Env::get_flags(unsigned int* flags) {
            return err_handler(mdb_env_get_flags(handle_, flags));
        }

        int Env::get_max_keysize(void) {
            if (!handle_) return 0;
            return mdb_env_get_maxkeysize(handle_);
        }

        int Env::get_max_readers(unsigned int* count) {
            return err_handler(mdb_env_get_maxreaders(handle_, count));
        }

        int Env::set_flags(const unsigned int flags, const bool onoff) {
            return err_handler(mdb_env_set_flags(handle_, flags, onoff ? 1 : 0));
        }

        int Env::set_mapsize(const size_t size) {
            return err_handler(mdb_env_set_mapsize(handle_, size));
        }

        int Env::set_max_dbs(const unsigned int count) {
            return err_handler(mdb_env_set_maxdbs(handle_, count));
        }

        int Env::set_max_readers(const unsigned int count) {
            return err_handler(mdb_env_set_maxreaders(handle_, count));
        }

        int Env::sync(const bool force) {
            return err_handler(mdb_env_sync(handle_, force));
        }

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

        MDB_txn* Txn::open_transaction(Env* parent_env, MDB_txn* parent_txn, unsigned int flags)
        {
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

        std::unique_ptr<Dbi> Txn::open_bucket(const char* name, unsigned int flags)
        {
            return std::make_unique<Dbi>(parent_env_, this, name, flags);
        }

        std::unique_ptr<Crs> Txn::open_cursor(MDB_dbi bucket)
        {
            return std::make_unique<Crs>(cursors_, parent_env_, this, bucket);
        }

        void Txn::close_cursors(void)
        {
            decltype(cursors_) tmp;
            std::swap(cursors_, tmp);
            for (auto& cursor : tmp) {
                cursor->close();
            }
        }

        void Txn::abort(void)
        {
            if (!handle_) return;
            close_cursors();
            mdb_txn_abort(handle_);
            if (is_ro()) {
                parent_env_->touch_ro_txns(-1);
            } else {
                parent_env_->touch_rw_txns(-1);
            }
            handle_ = nullptr;
        }

        int Txn::commit(void)
        {
            if (!handle_) return 0;
            close_cursors();
            int rc{err_handler(mdb_txn_commit(handle_))};
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

        Dbi::Dbi(Env* parent_env, Txn* parent_txn, MDB_dbi dbi)
            : parent_env_{parent_env}, parent_txn_{parent_txn}, handle_{dbi} {}

        MDB_dbi Dbi::open_bucket(Env* parent_env, Txn* parent_txn, const char* name, unsigned int flags)
        {
            if (!parent_env->is_opened() || !*parent_txn->handle()) {
                throw std::runtime_error("Database or transaction closed");
            }
            MDB_dbi retvar{0};
            (void)err_handler(mdb_dbi_open(*parent_txn->handle(), name, flags, &retvar), true);
            return retvar;
        }

        Dbi::Dbi(Env* env, Txn* txn, const char* name, unsigned int flags)
            : Dbi(env, txn, open_bucket(env, txn, name, flags)) {}

        int Dbi::get_flags(unsigned int* flags) {
            if (!opened_) {
                throw std::runtime_error("Closed or invalid handle");
            }
            return err_handler(mdb_dbi_flags(*parent_txn_->handle(), handle_, flags));
        }

        int Dbi::get_stat(MDB_stat* stat) {
            if (!opened_) {
                throw std::runtime_error("Closed or invalid handle");
            }
            return err_handler(mdb_stat(*parent_txn_->handle(), handle_, stat));
        }

        int Dbi::get(MDB_val* key, MDB_val* data) {
            if (!opened_) {
                throw std::runtime_error("Closed or invalid handle");
            }
            return err_handler(mdb_get(*parent_txn_->handle(), handle_, key, data));
        }

        int Dbi::del(MDB_val* key, MDB_val* data) {
            if (!opened_) {
                throw std::runtime_error("Closed or invalid handle");
            }
            return err_handler(mdb_del(*parent_txn_->handle(), handle_, key, data));
        }

        int Dbi::put(MDB_val* key, MDB_val* data, unsigned int flags) {
            if (!opened_) {
                throw std::runtime_error("Closed or invalid handle");
            }
            return err_handler(mdb_put(*parent_txn_->handle(), handle_, key, data, flags));
        }

        int Dbi::drop(int del) {
            int rc{err_handler(mdb_drop(*parent_txn_->handle(), handle_, del))};
            if (rc == MDB_SUCCESS && del) opened_ = false;
            return rc;
        }

        std::unique_ptr<Crs> Dbi::get_cursor(void) { return parent_txn_->open_cursor(handle_); }

        /*
        * Cursors
        */

        Crs::Crs(std::vector<Crs*>& coll, Env* parent_env, Txn* parent_txn, MDB_cursor* handle, MDB_dbi bucket)
            : coll_{&coll}, parent_env_{parent_env}, parent_txn_{parent_txn}, bucket_{bucket}, handle_{handle} {
            coll_->emplace_back(this);
        }

        MDB_cursor* Crs::open_cursor(Env* parent_env, Txn* parent_txn, MDB_dbi dbi)
        {
            if (!parent_env->is_opened() || !*parent_txn->handle()) {
                throw std::runtime_error("Database or transaction closed");
            }

            MDB_cursor* retvar{nullptr};
            (void)err_handler(mdb_cursor_open(*parent_txn->handle(), dbi, &retvar), true);
            return retvar;
        }

        Crs::Crs(std::vector<Crs*> &coll, Env* env, Txn* txn, MDB_dbi dbi) : Crs(coll, env, txn, open_cursor(env, txn, dbi), dbi) {}

        int Crs::get(MDB_val* key, MDB_val* data, MDB_cursor_op operation) {
            int rc{err_handler(mdb_cursor_get(handle_, key, data, operation))};
            return rc;
        }

        int Crs::seek(MDB_val* key, MDB_val* data) { return get(key, data, MDB_SET); }

        int Crs::current(MDB_val* key, MDB_val* data) { return get(key, data, MDB_GET_CURRENT); }

        int Crs::first(MDB_val* key, MDB_val* data) { return get(key, data, MDB_FIRST); }

        int Crs::prev(MDB_val* key, MDB_val* data) { return get(key, data, MDB_PREV); }

        int Crs::next(MDB_val* key, MDB_val* data) { return get(key, data, MDB_NEXT); }

        int Crs::last(MDB_val* key, MDB_val* data) { return get(key, data, MDB_LAST); }

        int Crs::del(unsigned int flags) { return err_handler(mdb_cursor_del(handle_, flags)); }

        int Crs::put(MDB_val* key, MDB_val* data, unsigned int flags) {
            return err_handler(mdb_cursor_put(handle_, key, data, flags));
        }

        int Crs::count(mdb_size_t* count) { return err_handler(mdb_cursor_count(handle_, count)); }

        void Crs::close() {

            // Remove self from collection of cursors
            // opened for this transaction
            if (coll_) {
                auto iter = std::find(coll_->begin(), coll_->end(), this);
                if (iter != coll_->end()) coll_->erase(iter);
                coll_ = nullptr;
            }

            // Eventually free handle
            if (handle_) {
                mdb_cursor_close(handle_);
                handle_ = nullptr;
            }
        }

}  // namespace lmdb

    std::shared_ptr<lmdb::Env> get_env(const char* path, const unsigned int flags, const mdb_mode_t mode)
    {
        struct Value {
            std::weak_ptr<lmdb::Env> wp;
            unsigned int flags;
        };

        static std::map<size_t, Value> s_envs;
        static std::mutex s_mtx;

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
        (void)newitem->set_mapsize(2ull << 40);
        (void)newitem->set_max_dbs(128);
        newitem->open(path, flags | MDB_NOTLS, mode); // Throws on error



        s_envs[envkey] = {newitem, flags};
        return newitem;
    }

}  // namespace silkworm::db
