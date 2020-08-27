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

    //boost::atomic<ChainDb*> ChainDb::singleton_;
    //boost::mutex ChainDb::singleton_mtx_;

    //ChainDb* ChainDb::instance()
    //{
    //    ChainDb* sin = singleton_.load();
    //    if (!sin) {
    //        boost::mutex::scoped_lock l(singleton_mtx_);
    //        sin = singleton_.load();
    //        if (!sin) {
    //            sin = new ChainDb();
    //            singleton_.store(sin);
    //        }
    //    }
    //    return sin;
    //}

    //void ChainDb::open(const char* path, const ChainDbOptions& options)
    //{
    //    try
    //    {
    //        boost::mutex::scoped_lock l(singleton_mtx_);
    //        if (env_.has_value() && env_->handle()) {
    //            throw std::runtime_error("Can't re-open");
    //        }
    //        env_ = lmdb::env::create();
    //        env_->set_max_dbs(options.max_buckets);
    //        env_->set_mapsize(options.map_size);
    //        env_->set_flags(MDB_NORDAHEAD);

    //        if (options.no_sync) {
    //            env_->set_flags(MDB_NOSYNC);
    //        }
    //        if (options.no_meta_sync) {
    //            env_->set_flags(MDB_NOMETASYNC);
    //        }
    //        if (options.write_map) {
    //            env_->set_flags(MDB_WRITEMAP);
    //        }
    //        if (options.no_sub_dir) {
    //            env_->set_flags(MDB_NOSUBDIR);
    //        }
    //        env_->open(path, 0, lmdb::env::default_mode);
    //    }
    //    catch (const std::exception& ex)
    //    {
    //        // Something gone wrong
    //        // TODO(Andrea) log error
    //        env_.reset();
    //    }

    //}

    //void ChainDb::close()
    //{
    //    boost::mutex::scoped_lock l(singleton_mtx_);
    //    if (env_.has_value() && env_->handle()) {
    //        env_->close();
    //    }
    //    env_.reset();
    //}

    //bool ChainDb::is_opened() { return (env_.has_value() && env_.value().handle()); }

    //std::optional<lmdb::env>& ChainDb::get_env() { return env_; }

}  // namespace silkworm::db
