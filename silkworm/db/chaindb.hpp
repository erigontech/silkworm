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

#include <lmdbxx/lmdb++.h>

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

    struct ChainDbOptions {
        uint64_t map_size = 2ull << 40;  // 2TiB by default
        bool no_sync = true;             // MDB_NOSYNC
        bool no_meta_sync = false;       // MDB_NOMETASYNC
        bool write_map = false;          // MDB_WRITEMAP
        bool no_sub_dir = false;         // MDB_NOSUBDIR
        unsigned max_buckets = 100;
    };


    class ChainDb {
       public:
        static ChainDb* instance();

        void open(const char* path, const ChainDbOptions& options = {});
        void close();

        bool is_opened();

        std::optional<lmdb::env>& get_env();

       private:
        ChainDb();
        ~ChainDb() = default;
        ChainDb(const ChainDb&) = delete;
        ChainDb& operator=(const ChainDb&) = delete;

        // Singleton
        static boost::atomic<ChainDb*> singleton_ ;
        static boost::mutex singleton_mtx_;

        // Lmdb
        std::optional<lmdb::env> env_{};
    };

}  // namespace silkworm::db

#endif  // SILKWORM_DB_CHAINDB_H_
