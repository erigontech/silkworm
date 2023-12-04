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
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/remote_state.hpp>
#include <silkworm/rpc/ethdb/cursor.hpp>
#include <silkworm/rpc/ethdb/transaction.hpp>

namespace silkworm::rpc::test {

//! This dummy transaction just gives you the same cursor over and over again.
class DummyTransaction : public ethdb::Transaction {
  public:
    explicit DummyTransaction(uint64_t view_id, std::shared_ptr<ethdb::CursorDupSort> cursor)
        : view_id_(view_id), cursor_(std::move(cursor)) {}

    [[nodiscard]] uint64_t view_id() const override { return view_id_; }

    Task<void> open() override { co_return; }

    Task<std::shared_ptr<ethdb::Cursor>> cursor(const std::string& /*table*/) override {
        co_return cursor_;
    }

    Task<std::shared_ptr<ethdb::CursorDupSort>> cursor_dup_sort(const std::string& /*table*/) override {
        co_return cursor_;
    }

    std::shared_ptr<silkworm::State> create_state(boost::asio::any_io_executor& executor, const core::rawdb::DatabaseReader& db_reader, const ChainStorage& storage,
                                                  BlockNum block_number) override {
        return std::make_shared<silkworm::rpc::state::RemoteState>(executor, db_reader, storage, block_number);
    }

    std::shared_ptr<ChainStorage> create_storage(const core::rawdb::DatabaseReader&, ethbackend::BackEnd*) override {
        return nullptr;
    }

    Task<void> close() override { co_return; }

  private:
    uint64_t view_id_;
    std::shared_ptr<ethdb::CursorDupSort> cursor_;
};

}  // namespace silkworm::rpc::test
