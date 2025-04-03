// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/db/kv/api/client.hpp>
#include <silkworm/db/kv/api/cursor.hpp>
#include <silkworm/db/kv/api/service.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/test_util/dummy_transaction.hpp>

namespace silkworm::rpc::test {

//! This dummy service acts as a factory for dummy transactions using the same cursor.
class DummyService : public db::kv::api::Service {
  public:
    DummyService(std::shared_ptr<db::kv::api::Cursor> cursor,
                 std::shared_ptr<db::kv::api::CursorDupSort> cursor_dup_sort,
                 test::BackEndMock* backend)
        : DummyService(0, 0, std::move(cursor), std::move(cursor_dup_sort), backend) {}
    DummyService(uint64_t tx_id,
                 uint64_t view_id,
                 std::shared_ptr<db::kv::api::Cursor> cursor,
                 std::shared_ptr<db::kv::api::CursorDupSort> cursor_dup_sort, test::BackEndMock* backend)
        : tx_id_(tx_id), view_id_(view_id), cursor_(std::move(cursor)), cursor_dup_sort_(std::move(cursor_dup_sort)), backend_(backend) {}

    Task<std::unique_ptr<db::kv::api::Transaction>> begin_transaction() override {
        co_return std::make_unique<DummyTransaction>(tx_id_, view_id_, cursor_, cursor_dup_sort_, backend_);
    }

    Task<db::kv::api::Version> version() override { co_return db::kv::api::kCurrentVersion; }
    Task<void> state_changes(const db::kv::api::StateChangeOptions&, db::kv::api::StateChangeConsumer) override { co_return; }

  private:
    uint64_t tx_id_;
    uint64_t view_id_;
    std::shared_ptr<db::kv::api::Cursor> cursor_;
    std::shared_ptr<db::kv::api::CursorDupSort> cursor_dup_sort_;
    test::BackEndMock* backend_;
};

//! This dummy client acts as a factory for dummy services.
class DummyClient : public db::kv::api::Client {
  public:
    DummyClient(std::shared_ptr<db::kv::api::Cursor> cursor,
                std::shared_ptr<db::kv::api::CursorDupSort> cursor_dup_sort,
                test::BackEndMock* backend)
        : DummyClient(0, 0, std::move(cursor), std::move(cursor_dup_sort), backend) {}
    DummyClient(uint64_t tx_id,
                uint64_t view_id,
                std::shared_ptr<db::kv::api::Cursor> cursor,
                std::shared_ptr<db::kv::api::CursorDupSort> cursor_dup_sort, test::BackEndMock* backend)
        : tx_id_(tx_id), view_id_(view_id), cursor_(std::move(cursor)), cursor_dup_sort_(std::move(cursor_dup_sort)), backend_(backend) {}

    std::shared_ptr<db::kv::api::Service> service() override {
        return std::make_shared<DummyService>(tx_id_, view_id_, cursor_, cursor_dup_sort_, backend_);
    }

  private:
    uint64_t tx_id_;
    uint64_t view_id_;
    std::shared_ptr<db::kv::api::Cursor> cursor_;
    std::shared_ptr<db::kv::api::CursorDupSort> cursor_dup_sort_;
    test::BackEndMock* backend_;
};

}  // namespace silkworm::rpc::test
