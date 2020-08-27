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

#include <string>

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

#define LMDB_ENABLE_EXCEPTIONS

namespace silkworm::db {

    class db_exception : public std::exception
    {
    public:
     db_exception(int err, const std::string errstr = NULL) : err_(err), errstr_(std::move(errstr)){};
     ~db_exception() noexcept {};
     virtual const char* what() noexcept {
         return errstr_.c_str();
     }
     int err() noexcept { return err_; }

    private:
     const int err_;
     const std::string errstr_;
    };

    namespace detail
    {
        std::string lmdb_err_string(int err) noexcept {
            switch (err) {
                case MDB_SUCCESS:
                    return "Success";  // We should never get here
                case MDB_KEYEXIST:
                    return "Key/Data pair already exists";
                case MDB_NOTFOUND:
                    return "Key/Data pair not found (EOF)";
                case MDB_PAGE_NOTFOUND:
                    return "Requested page not found - Possible database corruption";
                case MDB_CORRUPTED:
                    return "Located page was wrong type";
                case MDB_PANIC:
                    return "Update of meta page failed or environment had fatal error";
                case MDB_VERSION_MISMATCH:
                    return "Environment version mismatch";
                case MDB_INVALID:
                    return "File is not a valid LMDB file";
                case MDB_MAP_FULL:
                    return "Environment mapsize reached";
                case MDB_DBS_FULL:
                    return "Environment maxdbs reached";
                case MDB_READERS_FULL:
                    return "Environment maxreaders reached";
                case MDB_TLS_FULL:
                    return "Too many TLS keys in use";
                case MDB_TXN_FULL:
                    return "Transaction has too many dirty pages";
                case MDB_CURSOR_FULL:
                    return "Cursor stack too deep - internal error";
                case MDB_PAGE_FULL:
                    return "Page has not enough space - internal error";
                case MDB_MAP_RESIZED:
                    return "Database contents grew beyond environment mapsize";
                case MDB_INCOMPATIBLE:
                    return "Operation and DB incompatible, or DB type changed";
                case MDB_BAD_RSLOT:
                    return "Invalid reuse of reader locktable slot";
                case MDB_BAD_TXN:
                    return "Transaction must abort, has a child, or is invalid";
                case MDB_BAD_VALSIZE:
                    return "Unsupported size of key/DB name/data, or wrong DUPFIXED size";
                case MDB_BAD_DBI:
                    return "The specified DBI was changed unexpectedly";
                case MDB_PROBLEM:
                    return "Unexpected problem - txn should abort";
                default:
                    std::string ret{"Unrecognized error code : " + std::to_string(err)};
                    return ret;
            }
        }

        static inline int lmdb_err_handler(int err) {
#if defined(LMDB_ENABLE_EXCEPTIONS)
            if (err != MDB_SUCCESS) {
                throw db_exception(err, lmdb_err_string(err));
            }
#endif
            return err;
        }

        template <typename T>
        struct ReferenceReleaseHandler {
            static int release(T* arg) {
                (void)arg;
                return MDB_SUCCESS;
            }
        };

        // Basic wrapper class for native
        // Lmdb objects
        template<typename T>
        class Wrapper
        {
        public:
            typedef T lmdb_type;
        protected:
            lmdb_type* object_;
        public:
         Wrapper() : object_(NULL){};
         Wrapper(const lmdb_type&& obj) : object_(obj){};
         Wrapper(const Wrapper<lmdb_type>& rhs) {
             lmdb_err_handler(release());
             object_ = rhs.object_;
         }
         Wrapper(Wrapper<lmdb_type>&& rhs) {
             object_ = rhs.object_;
             rhs.object_ = NULL;
         }
         Wrapper<lmdb_type>& operator=(const Wrapper<lmdb_type>& rhs) {
             if (this != &rhs) {
                 lmdb_err_handler(release());
                 object_ = rhs.object_;
             }
             return *this;
         }
         Wrapper<lmdb_type>& operator=(Wrapper<lmdb_type>& rhs) {
             if (this != &rhs) {
                 lmdb_err_handler(release());
                 object_ = rhs.object_;
                 rhs.object_ = NULL;
             }
             return *this;
         }
         Wrapper<lmdb_type>& operator=(const lmdb_type&& rhs) {
             lmdb_err_handler(release());
             object_ = rhs;
             return *this;
         }
         const lmdb_type& operator ()() const { return object_; }
         lmdb_type& operator ()() { return object_; }
         const lmdb_type get() { return object_; }
         ~Wrapper() {
             if (object_ != NULL) release();
         };

        protected:

         int release() {
             if (object_ != NULL) {
                 return ReferenceReleaseHandler<lmdb_type>::release(object_);
             }
             return MDB_SUCCESS;
         }
        };

    } //namespace detail


    class Env : public detail::Wrapper<MDB_env> {
       public:

           static constexpr unsigned int default_flags{ 0 };
           static constexpr mdb_mode_t default_mode{ 0644 };

           void close() noexcept {
               // TODO(Andrea) check it was not previously closed
               mdb_env_close(object_);
           }

           void create(const unsigned flags = default_flags, int* rc = NULL) {
               int res{detail::lmdb_err_handler(mdb_env_create(&object_))};
               if (rc != NULL) {
                   *rc = res;
                   if (res != MDB_SUCCESS) return;
               };

               if (!flags) return;
               res = detail::lmdb_err_handler(mdb_env_set_flags(object_, flags, 1));
               if (res) {
                   if (rc != NULL) *rc = res;
                   mdb_env_close(object_);
               }
           }

           void open(const char* path, const unsigned int flags = default_flags, const mdb_mode_t mode = default_mode, int* rc = NULL) {
               int res{detail::lmdb_err_handler(mdb_env_open(object_, path, flags, mode))};
               if (rc != NULL) *rc = res;
               if (res != MDB_SUCCESS) close();
           }

           void sync(const bool force = true, int* rc = NULL) {
               int res{detail::lmdb_err_handler(mdb_env_sync(object_, force))};
               if (rc != NULL) *rc = res;
           }


    };

    struct ChainDbOptions {
        uint64_t map_size = 2ull << 40;  // 2TiB by default
        bool no_sync = true;             // MDB_NOSYNC
        bool no_meta_sync = false;       // MDB_NOMETASYNC
        bool write_map = false;          // MDB_WRITEMAP
        bool no_sub_dir = false;         // MDB_NOSUBDIR
        unsigned max_buckets = 100;
    };


    //class ChainDb {
    //   public:

    //    static ChainDb* instance();

    //    void open(const char* path, const ChainDbOptions& options = {});
    //    void close();

    //    bool is_opened();

    //    std::optional<lmdb::env>& get_env();

    //   private:
    //    ChainDb() = default;
    //    ~ChainDb() = default;
    //    ChainDb(const ChainDb&) = delete;
    //    ChainDb& operator=(const ChainDb&) = delete;

    //    // Singleton
    //    static boost::atomic<ChainDb*> singleton_ ;
    //    static boost::mutex singleton_mtx_;

    //    // Lmdb
    //    std::optional<lmdb::env> env_{};
    //};

}  // namespace silkworm::db

#endif  // SILKWORM_DB_CHAINDB_H_
