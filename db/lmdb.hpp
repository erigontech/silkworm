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

// TODO(Andrew) comments

#ifndef SILKWORM_DB_LMDB_H_
#define SILKWORM_DB_LMDB_H_

#include <lmdb.h>
#include <stdint.h>

#include <boost/filesystem.hpp>
#include <string_view>

#include "database.hpp"

namespace silkworm::db {

struct LmdbOptions {
  uint64_t map_size = 4ull << 40;  // 4TB by default
  bool no_sync = false;            // MDB_NOSYNC
  bool no_meta_sync = false;       // MDB_NOMETASYNC
  bool write_map = false;          // MDB_WRITEMAP
};

/*
class LmdbBucket : public Bucket {
 public:
  void put(std::string_view key, std::string_view val) override;

  std::optional<std::string_view> get(std::string_view key) const override;
};

class LmdbTransaction : public Transaction {
 public:
  std::unique_ptr<Bucket> get_bucket(std::string_view name) override;

  bool create_bucket(std::string_view name) override;

  void commit() override;

  void rollback() override;
};
*/

// Must not create several instances of the same database.
class LmdbDatabase : public Database {
 public:
  explicit LmdbDatabase(const char* path, const LmdbOptions& options = {});
  ~LmdbDatabase() override;

  // std::unique_ptr<Transaction> new_txn() override;

 private:
  MDB_env* env_{nullptr};
};

class TemporaryLmdbDatabase : public LmdbDatabase {
 public:
  TemporaryLmdbDatabase();
  ~TemporaryLmdbDatabase() override;

 private:
  boost::filesystem::path tmp_dir_;
};
}  // namespace silkworm::db

#endif  // SILKWORM_DB_LMDB_H_
