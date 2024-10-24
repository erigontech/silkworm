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
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>
#include <silkworm/rpc/test_util/mock_back_end.hpp>

namespace silkworm::rpc::test {

template <typename Paginated>
inline Paginated empty_paginated_sequence() {
    auto paginator = []() -> Task<typename Paginated::PageResult> {
        co_return typename Paginated::PageResult{};
    };
    return Paginated{paginator};
}

inline db::kv::api::PaginatedTimestamps empty_paginated_timestamps() {
    return empty_paginated_sequence<db::kv::api::PaginatedTimestamps>();
}

inline db::kv::api::PaginatedKeysValues empty_paginated_keys_and_values() {
    return empty_paginated_sequence<db::kv::api::PaginatedKeysValues>();
}

//! This dummy transaction just gives you the same cursor over and over again.
class DummyTransaction : public db::kv::api::BaseTransaction {
  public:
    explicit DummyTransaction(uint64_t tx_id,
                              uint64_t view_id,
                              std::shared_ptr<db::kv::api::Cursor> cursor,
                              std::shared_ptr<db::kv::api::CursorDupSort> cursor_dup_sort,
                              test::BackEndMock* backend)
        : BaseTransaction(nullptr), tx_id_(tx_id), view_id_(view_id), cursor_(std::move(cursor)), cursor_dup_sort_(std::move(cursor_dup_sort)), backend_(backend) {}

    uint64_t tx_id() const override { return tx_id_; }
    uint64_t view_id() const override { return view_id_; }

    Task<void> open() override { co_return; }

    Task<std::shared_ptr<db::kv::api::Cursor>> cursor(const std::string& /*table*/) override {
        co_return cursor_;
    }

    Task<std::shared_ptr<db::kv::api::CursorDupSort>> cursor_dup_sort(const std::string& /*table*/) override {
        co_return cursor_dup_sort_;
    }

    std::shared_ptr<silkworm::State> create_state(boost::asio::any_io_executor& executor, const db::chain::ChainStorage& storage, BlockNum block_number) override {
        return std::make_shared<db::state::RemoteState>(executor, *this, storage, block_number, db::chain::Providers{});
    }

    std::shared_ptr<db::chain::ChainStorage> create_storage() override {
        return std::make_shared<db::chain::RemoteChainStorage>(*this, ethdb::kv::make_backend_providers(backend_));
    }

    Task<void> close() override { co_return; }

    // NOLINTNEXTLINE(*-rvalue-reference-param-not-moved)
    Task<db::kv::api::DomainPointResult> domain_get(db::kv::api::DomainPointQuery&& /*query*/) override {
        co_return db::kv::api::DomainPointResult{};
    }

    // NOLINTNEXTLINE(*-rvalue-reference-param-not-moved)
    Task<db::kv::api::HistoryPointResult> history_seek(db::kv::api::HistoryPointQuery&& /*query*/) override {
        co_return db::kv::api::HistoryPointResult{};
    }

    // NOLINTNEXTLINE(*-rvalue-reference-param-not-moved)
    Task<db::kv::api::PaginatedTimestamps> index_range(db::kv::api::IndexRangeQuery&& /*query*/) override {
        co_return empty_paginated_timestamps();
    }

    // NOLINTNEXTLINE(*-rvalue-reference-param-not-moved)
    Task<db::kv::api::PaginatedKeysValues> history_range(db::kv::api::HistoryRangeQuery&& /*query*/) override {
        co_return empty_paginated_keys_and_values();
    }

    // NOLINTNEXTLINE(*-rvalue-reference-param-not-moved)
    Task<db::kv::api::PaginatedKeysValues> domain_range(db::kv::api::DomainRangeQuery&& /*query*/) override {
        co_return test::empty_paginated_keys_and_values();
    }

  private:
    uint64_t tx_id_;
    uint64_t view_id_;
    std::shared_ptr<db::kv::api::Cursor> cursor_;
    std::shared_ptr<db::kv::api::CursorDupSort> cursor_dup_sort_;
    test::BackEndMock* backend_;
};

}  // namespace silkworm::rpc::test
