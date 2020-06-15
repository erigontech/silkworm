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

#include "lmdbxx/lmdb++.h"

namespace {
thread_local boost::filesystem::path last_tmp_dir;

const char* new_tmp_dir() {
  last_tmp_dir = boost::filesystem::unique_path();
  boost::filesystem::create_directories(last_tmp_dir);
  return last_tmp_dir.c_str();
}

MDB_val to_mdb_val(const std::string_view view) { return {view.size(), const_cast<char*>(view.data())}; }

std::string_view from_mdb_val(const MDB_val val) { return {static_cast<char*>(val.mv_data), val.mv_size}; }
}  // namespace

namespace silkworm::db {

LmdbBucket::LmdbBucket(MDB_dbi dbi, MDB_txn* txn) : dbi_{dbi}, txn_{txn} {}

void LmdbBucket::put(std::string_view key, std::string_view value) {
  MDB_val key_mdb = to_mdb_val(key);
  MDB_val val_mdb = to_mdb_val(value);
  lmdb::dbi_put(txn_, dbi_, &key_mdb, &val_mdb);
}

std::optional<std::string_view> LmdbBucket::get(std::string_view key) const {
  MDB_val key_val = to_mdb_val(key);
  MDB_val data;
  bool found = lmdb::dbi_get(txn_, dbi_, &key_val, &data);
  if (found) {
    // TODO(Andrew) either copy or make the ramifications crystall clear in the API
    return from_mdb_val(data);
  } else {
    return {};
  }
}

LmdbTransaction::LmdbTransaction(MDB_txn* txn) : txn_{txn} {};

LmdbTransaction::~LmdbTransaction() {
  if (txn_) {
    mdb_txn_abort(txn_);
    txn_ = nullptr;
  }
}

std::unique_ptr<Bucket> LmdbTransaction::create_bucket(const char* name) {
  MDB_dbi dbi;
  lmdb::dbi_open(txn_, name, MDB_CREATE, &dbi);
  return std::unique_ptr<LmdbBucket>{new LmdbBucket{dbi, txn_}};
}

std::unique_ptr<Bucket> LmdbTransaction::get_bucket(const char* name) {
  MDB_dbi dbi;
  lmdb::dbi_open(txn_, name, /*flags=*/0, &dbi);
  return std::unique_ptr<LmdbBucket>{new LmdbBucket{dbi, txn_}};
}

void LmdbTransaction::commit() {
  lmdb::txn_commit(txn_);
  txn_ = nullptr;
}

void LmdbTransaction::rollback() {
  lmdb::txn_abort(txn_);
  txn_ = nullptr;
}

LmdbDatabase::LmdbDatabase(const char* path, const LmdbOptions& options) {
  lmdb::env_create(&env_);
  lmdb::env_set_max_dbs(env_, options.max_buckets);
  static_assert(sizeof(size_t) >= sizeof(uint64_t), "32 bit mode limits max LMDB size");
  lmdb::env_set_mapsize(env_, options.map_size);
  unsigned flags{0};
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

std::unique_ptr<Transaction> LmdbDatabase::begin_transaction(bool read_only) {
  unsigned flags{0};
  if (read_only) {
    flags |= MDB_RDONLY;
  }
  MDB_txn* txn{nullptr};
  lmdb::txn_begin(env_, /*parent=*/nullptr, flags, &txn);
  return std::unique_ptr<LmdbTransaction>{new LmdbTransaction{txn}};
}

TemporaryLmdbDatabase::TemporaryLmdbDatabase()
    : LmdbDatabase{new_tmp_dir(),
                   LmdbOptions{
                       .map_size = 64 << 20,  // 64MB
                       .no_sync = true,
                       .no_meta_sync = true,
                       .write_map = true,
                   }},
      tmp_dir_{last_tmp_dir} {}

TemporaryLmdbDatabase::~TemporaryLmdbDatabase() {
  boost::system::error_code ec;
  boost::filesystem::remove_all(tmp_dir_, ec);
}

}  // namespace silkworm::db
