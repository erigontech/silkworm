// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/db/chain/remote_chain_storage.hpp>
#include <silkworm/db/kv/api/base_transaction.hpp>
#include <silkworm/db/kv/api/cursor.hpp>
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>
#include <silkworm/rpc/test_util/mock_back_end.hpp>

namespace silkworm::rpc::test {

template <typename Paginated>
inline Paginated empty_paginated_sequence() {
    auto paginator = [](typename Paginated::PageToken) -> Task<typename Paginated::PageResult> {
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
    DummyTransaction(uint64_t tx_id,
                     uint64_t view_id,
                     std::shared_ptr<db::kv::api::Cursor> cursor,
                     std::shared_ptr<db::kv::api::CursorDupSort> cursor_dup_sort,
                     test::BackEndMock* backend)
        : BaseTransaction{nullptr},
          tx_id_(tx_id),
          view_id_(view_id),
          cursor_(std::move(cursor)),
          cursor_dup_sort_(std::move(cursor_dup_sort)),
          backend_(backend) {}

    uint64_t tx_id() const override { return tx_id_; }
    uint64_t view_id() const override { return view_id_; }

    Task<void> open() override { co_return; }

    Task<std::shared_ptr<db::kv::api::Cursor>> cursor(const std::string& /*table*/) override {
        co_return cursor_;
    }

    Task<std::shared_ptr<db::kv::api::CursorDupSort>> cursor_dup_sort(const std::string& /*table*/) override {
        co_return cursor_dup_sort_;
    }

    std::shared_ptr<db::chain::ChainStorage> make_storage() override {
        return std::make_shared<db::chain::RemoteChainStorage>(*this, ethdb::kv::make_backend_providers(backend_));
    }

    Task<TxnId> first_txn_num_in_block(BlockNum /*block_num*/) override {
        co_return 0;
    }

    Task<void> close() override { co_return; }

    Task<db::kv::api::GetLatestResult> get_latest(db::kv::api::GetLatestRequest /*query*/) override {
        co_return db::kv::api::GetLatestResult{};
    }

    Task<db::kv::api::GetAsOfResult> get_as_of(db::kv::api::GetAsOfRequest /*query*/) override {
        co_return db::kv::api::GetAsOfResult{};
    }

    Task<db::kv::api::HistoryPointResult> history_seek(db::kv::api::HistoryPointRequest /*query*/) override {
        co_return db::kv::api::HistoryPointResult{};
    }

    Task<db::kv::api::PaginatedTimestamps> index_range(db::kv::api::IndexRangeRequest /*query*/) override {
        co_return empty_paginated_timestamps();
    }

    Task<db::kv::api::PaginatedKeysValues> history_range(db::kv::api::HistoryRangeRequest /*query*/) override {
        co_return empty_paginated_keys_and_values();
    }

    Task<db::kv::api::PaginatedKeysValues> range_as_of(db::kv::api::DomainRangeRequest /*query*/) override {
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
