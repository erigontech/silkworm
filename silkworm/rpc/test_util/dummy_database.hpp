/*
   Copyright 2023 The Silkworm Authors

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

#pragma once

#include <memory>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/db/kv/api/cursor.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/ethdb/database.hpp>
#include <silkworm/rpc/ethdb/transaction.hpp>
#include <silkworm/rpc/test/dummy_transaction.hpp>

namespace silkworm::rpc::test {

//! This dummy database acts as a factory for dummy transactions using the same cursor.
class DummyDatabase : public ethdb::Database {
  public:
    explicit DummyDatabase(uint64_t tx_id, std::shared_ptr<ethdb::CursorDupSort> cursor)
        : tx_id_(tx_id), cursor_(std::move(cursor)) {}

    Task<std::unique_ptr<ethdb::Transaction>> begin() override {
        co_return std::make_unique<DummyTransaction>(tx_id_, cursor_);
    }

  private:
    uint64_t tx_id_;
    std::shared_ptr<ethdb::CursorDupSort> cursor_;
};

}  // namespace silkworm::rpc::test
