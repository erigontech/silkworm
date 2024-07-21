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
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/ethdb/database.hpp>
#include <silkworm/rpc/test_util/dummy_transaction.hpp>

namespace silkworm::rpc::test {

//! This dummy database acts as a factory for dummy transactions using the same cursor.
class DummyDatabase : public ethdb::Database {
  public:
    explicit DummyDatabase(std::shared_ptr<db::kv::api::Cursor> cursor,
                           std::shared_ptr<db::kv::api::CursorDupSort> cursor_dup_sort)
        : DummyDatabase(0, 0, std::move(cursor), std::move(cursor_dup_sort)) {}
    DummyDatabase(uint64_t tx_id,
                  uint64_t view_id,
                  std::shared_ptr<db::kv::api::Cursor> cursor,
                  std::shared_ptr<db::kv::api::CursorDupSort> cursor_dup_sort)
        : tx_id_(tx_id), view_id_(view_id), cursor_(std::move(cursor)), cursor_dup_sort_(std::move(cursor_dup_sort)) {}

    Task<std::unique_ptr<db::kv::api::Transaction>> begin() override {
        co_return std::make_unique<DummyTransaction>(tx_id_, view_id_, cursor_, cursor_dup_sort_);
    }

  private:
    uint64_t tx_id_;
    uint64_t view_id_;
    std::shared_ptr<db::kv::api::Cursor> cursor_;
    std::shared_ptr<db::kv::api::CursorDupSort> cursor_dup_sort_;
};

}  // namespace silkworm::rpc::test
