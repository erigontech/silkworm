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

#include <lmdbxx/lmdb++.h>

#include <cstdio>
#include <memory>

namespace silkworm::db {

static MDB_val to_mdb_val(ByteView view) {
  MDB_val val;
  val.mv_data = const_cast<uint8_t*>(view.data());
  val.mv_size = view.size();
  return val;
}

static ByteView from_mdb_val(const MDB_val val) {
  auto* ptr{static_cast<uint8_t*>(val.mv_data)};
  return {ptr, val.mv_size};
}

LmdbCursor::~LmdbCursor() {
  if (cursor_) {
    lmdb::cursor_close(cursor_);
    cursor_ = nullptr;
  }
}

std::optional<Entry> LmdbCursor::seek(ByteView prefix) {
  MDB_val key{to_mdb_val(prefix)};
  MDB_val value;
  MDB_cursor_op op{prefix.empty() ? MDB_FIRST : MDB_SET_RANGE};
  bool found = lmdb::cursor_get(cursor_, &key, &value, op);
  if (!found) return {};

  return Entry{.key = from_mdb_val(key), .value = from_mdb_val(value)};
}

LmdbBucket::LmdbBucket(MDB_dbi dbi, MDB_txn* txn) : dbi_{dbi}, txn_{txn} {}

void LmdbBucket::put(ByteView key, ByteView value) {
  MDB_val key_mdb = to_mdb_val(key);
  MDB_val val_mdb = to_mdb_val(value);
  lmdb::dbi_put(txn_, dbi_, &key_mdb, &val_mdb);
}

std::optional<ByteView> LmdbBucket::get(ByteView key) const {
  MDB_val key_val = to_mdb_val(key);
  MDB_val data;
  bool found = lmdb::dbi_get(txn_, dbi_, &key_val, &data);
  if (!found) return {};

  // TODO(Andrew) either copy or make the ramifications crystall clear in the API
  return from_mdb_val(data);
}

std::unique_ptr<Cursor> LmdbBucket::cursor() {
  MDB_cursor* cursor{};
  lmdb::cursor_open(txn_, dbi_, &cursor);
  return std::make_unique<LmdbCursor>(cursor);
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
  return std::make_unique<LmdbBucket>(dbi, txn_);
}

std::unique_ptr<Bucket> LmdbTransaction::get_bucket(const char* name) {
  MDB_dbi dbi;
  lmdb::dbi_open(txn_, name, /*flags=*/0, &dbi);
  return std::make_unique<LmdbBucket>(dbi, txn_);
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
  unsigned flags{MDB_NORDAHEAD};
  if (options.no_sync) {
    flags |= MDB_NOSYNC;
  }
  if (options.no_meta_sync) {
    flags |= MDB_NOMETASYNC;
  }
  if (options.write_map) {
    flags |= MDB_WRITEMAP;
  }
  if (options.no_sub_dir) {
    flags |= MDB_NOSUBDIR;
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
  return std::make_unique<LmdbTransaction>(txn);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static char* temporary_file_name() { return std::tmpnam(nullptr); }
#pragma GCC diagnostic pop

TemporaryLmdbDatabase::TemporaryLmdbDatabase()
    : LmdbDatabase{temporary_file_name(),
                   LmdbOptions{
                       .map_size = 32 << 20,  // 32MiB
                       .no_sync = true,
                       .no_meta_sync = true,
                       .write_map = true,
                       .no_sub_dir = true,
                   }} {
  mdb_env_get_path(env_, &tmp_file_);
}

TemporaryLmdbDatabase::~TemporaryLmdbDatabase() {
  if (env_) {
    mdb_env_close(env_);
    env_ = nullptr;
  }

  if (tmp_file_) {
    std::remove(tmp_file_);
    tmp_file_ = nullptr;
  }
}
}  // namespace silkworm::db
