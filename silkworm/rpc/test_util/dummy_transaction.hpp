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

#include <silkworm/db/chain/remote_chain_storage.hpp>
#include <silkworm/db/kv/api/base_transaction.hpp>
#include <silkworm/db/kv/api/cursor.hpp>
#include <silkworm/db/state/remote_state.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>
#include <silkworm/rpc/test_util/mock_back_end.hpp>

namespace silkworm::rpc::test {

inline db::kv::api::PaginatedTimestamps::Paginator empty_paginator(db::kv::api::IndexRangeQuery&& query) {
    return [query = std::move(query)]() mutable -> Task<db::kv::api::PaginatedTimestamps::PageResult> {
        co_return db::kv::api::PaginatedTimestamps::PageResult{};
    };
}

//! This dummy transaction just gives you the same cursor over and over again.
class DummyTransaction : public db::kv::api::BaseTransaction {
  public:
    explicit DummyTransaction(uint64_t tx_id,
                              uint64_t view_id,
                              std::shared_ptr<db::kv::api::Cursor> cursor,
                              std::shared_ptr<db::kv::api::CursorDupSort> cursor_dup_sort)
        : BaseTransaction(nullptr), tx_id_(tx_id), view_id_(view_id), cursor_(std::move(cursor)), cursor_dup_sort_(std::move(cursor_dup_sort)) {}

    [[nodiscard]] uint64_t tx_id() const override { return tx_id_; }
    [[nodiscard]] uint64_t view_id() const override { return view_id_; }

    Task<void> open() override { co_return; }

    Task<std::shared_ptr<db::kv::api::Cursor>> cursor(const std::string& /*table*/) override {
        co_return cursor_;
    }

    Task<std::shared_ptr<db::kv::api::CursorDupSort>> cursor_dup_sort(const std::string& /*table*/) override {
        co_return cursor_dup_sort_;
    }

    std::shared_ptr<silkworm::State> create_state(boost::asio::any_io_executor& executor, const db::chain::ChainStorage& storage, BlockNum block_number) override {
        return std::make_shared<db::state::RemoteState>(executor, *this, storage, block_number);
    }

    std::shared_ptr<db::chain::ChainStorage> create_storage() override {
        return std::make_shared<db::chain::RemoteChainStorage>(*this, ethdb::kv::block_provider(&backend_), ethdb::kv::block_number_from_txn_hash_provider(&backend_));
    }

    Task<void> close() override { co_return; }

    Task<db::kv::api::PaginatedTimestamps> index_range(db::kv::api::IndexRangeQuery&& query) override {
        co_return db::kv::api::PaginatedTimestamps{empty_paginator(std::move(query))};
    }

  private:
    uint64_t tx_id_;
    uint64_t view_id_;
    std::shared_ptr<db::kv::api::Cursor> cursor_;
    std::shared_ptr<db::kv::api::CursorDupSort> cursor_dup_sort_;
    test::BackEndMock backend_;
};

}  // namespace silkworm::rpc::test
