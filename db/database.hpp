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

#ifndef SILKWORM_DB_DATABASE_H_
#define SILKWORM_DB_DATABASE_H_

#include <memory>
#include <optional>
#include <string_view>

namespace silkworm::db {

/*
class Bucket {
 public:
  Bucket(const Bucket&) = delete;
  Bucket& operator=(const Bucket&) = delete;

  virtual void put(std::string_view key, std::string_view val) = 0;

  virtual std::optional<std::string_view> get(std::string_view key) const = 0;

 protected:
  virtual ~Bucket() = default;
};

class Transaction {
 public:
  Transaction(const Transaction&) = delete;
  Transaction& operator=(const Transaction&) = delete;

  virtual std::unique_ptr<Bucket> get_bucket(std::string_view name) = 0;

  virtual bool create_bucket(std::string_view name) = 0;

  virtual void commit() = 0;

  virtual void rollback() = 0;

 protected:
  Transaction() = default;
  virtual ~Transaction() = default;
};
*/

class Database {
 public:
  Database(const Database&) = delete;
  Database& operator=(const Database&) = delete;

  // virtual std::unique_ptr<Transaction> new_txn();

 protected:
  Database() = default;
  virtual ~Database() = default;
};

}  // namespace silkworm::db

#endif  // SILKWORM_DB_DATABASE_H_
