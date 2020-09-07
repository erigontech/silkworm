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

#ifndef SILKWORM_DB_CHAINDB_H_
#define SILKWORM_DB_CHAINDB_H_

#include <boost/atomic.hpp>
#include <boost/thread.hpp>

#include <lmdb/lmdb.h>

#include <iostream>
#include <string>
#include <thread>

// Check windows
#if _WIN32 || _WIN64
#if _WIN64
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

// Check GCC
#if __GNUC__
#if __x86_64__ || __ppc64__
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

#ifndef ENVIRONMENT64
#error "32 bit environment limits LMDB size"
#endif // !ENVIRONMENT64

namespace silkworm::db {

    namespace lmdb {

        // An exception thrown by lmdb.
        class exception : public std::exception {
           public:
            exception(int err, const char* errstr) : err_{err}, message_{std::move(errstr)} {};
            virtual const char* what() noexcept { return message_; }
            int err() { return err_; }
           private:
            int err_;
            const char* message_;
        };

        static inline int err_handler(int err, bool shouldthrow = false) {
            if (err != MDB_SUCCESS && shouldthrow) {
                throw exception(err, mdb_strerror(err));
            }
            return err;
        }

        class Env;  // environment : 1:1 relation among env and opened files
        class Txn;  // transaction : every read write operation lives in a transaction
        class Dbi;  // named database interface (aka bucket)
        class Crs;  // cursor for a bucket

        class Env {

        private:

            MDB_env* handle_{nullptr};

            bool opened_{false};
            std::mutex count_mtx_;

            std::map<std::thread::id, int> ro_txns_{};
            std::map<std::thread::id, int> rw_txns_{};

           public:
            static constexpr unsigned int default_flags{0};
            static constexpr mdb_mode_t default_mode{0644};

            Env(const unsigned flags = default_flags);
            ~Env() noexcept;

            MDB_env** handle(void) { return &handle_; }
            bool is_opened(void) { return opened_; }
            bool is_ro(void);

            void open(const char* path, const unsigned int flags = default_flags, const mdb_mode_t mode = default_mode);
            void close() noexcept;

            int get_flags(unsigned int* flags);
            int get_max_keysize(void);
            int get_max_readers(unsigned int* count);

            int set_flags(const unsigned int flags, const bool onoff = true);
            int set_mapsize(const size_t size);
            int set_max_dbs(const unsigned int count);
            int set_max_readers(const unsigned int count);
            int sync(const bool force = true);

            int get_ro_txns(void);
            int get_rw_txns(void);
            void touch_ro_txns(int count);
            void touch_rw_txns(int count);

            std::unique_ptr<Txn> begin_transaction(unsigned int flags = 0);
            std::unique_ptr<Txn> begin_ro_transaction(unsigned int flags = 0);
            std::unique_ptr<Txn> begin_rw_transaction(unsigned int flags = 0);

        };

        class Txn {

           protected:

            Env* parent_env_;
            MDB_txn* handle_;
            unsigned int flags_;
            Txn(Env* parent, MDB_txn* txn, unsigned int flags);

           private:
            static MDB_txn* open_transaction(Env* parent_env, MDB_txn* parent_txn, unsigned int flags = 0);

            std::vector<Crs*> cursors_{};

           public:
            explicit Txn(Env* parent, unsigned int flags = 0);
            ~Txn();

            MDB_txn** handle() { return &handle_; }
            bool is_ro(void);

            std::unique_ptr<Dbi> open_bucket(const char* name, unsigned int flags = 0);
            std::unique_ptr<Crs> open_cursor(MDB_dbi bucket);

            Txn(const Txn& src) = delete;
            Txn& operator=(const Txn& src) = delete;
            Txn(Txn&& rhs) = delete;
            Txn& operator=(Txn&& rhs) = delete;

            void close_cursors(void);
            void abort(void);
            int commit(void);
        };

        class Dbi {
           protected:
            Dbi(Env* parent_env, Txn* parent_txn, MDB_dbi dbi);

           private:
            static MDB_dbi open_bucket(Env* parent_env, Txn* parent_txn, const char* name, unsigned int flags = 0);

           public:
            explicit Dbi(Env* env, Txn* txn, const char* name, unsigned int flags = 0);

            int get_flags(unsigned int* flags);
            int get_stat(MDB_stat* stat);
            int get(MDB_val* key, MDB_val* data);
            int del(MDB_val* key, MDB_val* data);
            int put(MDB_val* key, MDB_val* data, unsigned int flags = 0);
            int drop(int del);

            std::unique_ptr<Crs> get_cursor(void);

           private:
            Env* parent_env_;
            Txn* parent_txn_;
            MDB_dbi handle_;
            bool opened_{true};
        };

        class Crs {

        protected:

            Crs(std::vector<Crs*> &coll, Env* parent_env, Txn* parent_txn, MDB_cursor* handle, MDB_dbi bucket);

        private:

            static MDB_cursor* open_cursor(Env* parent_env, Txn* parent_txn, MDB_dbi dbi);

        public:
         explicit Crs(std::vector<Crs*> &coll, Env* env, Txn* txn, MDB_dbi dbi);
         int get(MDB_val* key, MDB_val* data, MDB_cursor_op operation);  // Gets data on behalf of operation
         int seek(MDB_val* key, MDB_val* data);                          // Tries find a key in bucket
         int current(MDB_val* key, MDB_val* data);                       // Gets data from current cursor position
         int first(MDB_val* key, MDB_val* data);                         // Move cursor at first item in bucket
         int prev(MDB_val* key, MDB_val* data);                          // Move cursor at previous item in bucket
         int next(MDB_val* key, MDB_val* data);                          // Move cursor at next item in bucket
         int last(MDB_val* key, MDB_val* data);                          // Move cursor at last item in bucket
         int del(unsigned int flags = 0);                                // Delete key/data pair at current position
         int put(MDB_val* key, MDB_val* data, unsigned int flags = 0);   // Store data by cursor
         int count(mdb_size_t* count);  // Returns the count of duplicates at current position
         void close(void);              // Close the cursor and frees the handle
        private:
         std::vector<Crs*>* coll_;
         Env* parent_env_;
         Txn* parent_txn_;
         MDB_dbi bucket_;
         MDB_cursor* handle_;
        };

    }  // namespace lmdb


    std::shared_ptr<lmdb::Env> get_env(const char* path, const unsigned int flags = lmdb::Env::default_flags,
                                       const mdb_mode_t mode = lmdb::Env::default_mode);

}  // namespace silkworm::db

#endif  // SILKWORM_DB_CHAINDB_H_
