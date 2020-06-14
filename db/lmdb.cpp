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

#include "lmdb.hpp"

#include "../externals/lmdbxx/lmdb++.h"

namespace {
thread_local boost::filesystem::path last_tmp_dir;

const char* new_tmp_dir() {
  last_tmp_dir = boost::filesystem::unique_path();
  boost::filesystem::create_directories(last_tmp_dir);
  return last_tmp_dir.c_str();
}
}  // namespace

namespace silkworm::db {

static_assert(sizeof(size_t) >= sizeof(uint64_t), "32 bit mode limits max LMDB size");

LmdbDatabase::LmdbDatabase(const char* path, const LmdbOptions& options) {
  lmdb::env_create(&env_);
  lmdb::env_set_mapsize(env_, options.map_size);
  unsigned flags = 0;
  if (options.no_sync) {
    flags |= MDB_NOSYNC;
  }
  if (options.no_meta_sync) {
    flags |= MDB_NOMETASYNC;
  }
  if (options.write_map) {
    flags |= MDB_WRITEMAP;
  }
  lmdb::env_open(env_, path, flags, lmdb::env::default_mode);
}

LmdbDatabase::~LmdbDatabase() {
  if (env_) {
    mdb_env_close(env_);
    env_ = nullptr;
  }
}

TemporaryLmdbDatabase::TemporaryLmdbDatabase()
    : LmdbDatabase{new_tmp_dir(),
                   LmdbOptions{
                       .map_size = 32 << 20,  // 32MB
                       .no_sync = true,
                       .no_meta_sync = true,
                       .write_map = true,
                   }},
      tmp_dir_{last_tmp_dir} {}

TemporaryLmdbDatabase::~TemporaryLmdbDatabase() {
  if (!tmp_dir_.empty()) {
    boost::system::error_code ec;
    boost::filesystem::remove_all(tmp_dir_, ec);
  }
}

}  // namespace silkworm::db
