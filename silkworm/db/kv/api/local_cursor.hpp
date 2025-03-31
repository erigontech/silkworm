// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/use_awaitable.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>

#include "cursor.hpp"

namespace silkworm::db::kv::api {

class LocalCursor : public CursorDupSort {
  public:
    LocalCursor(mdbx::txn& txn, uint32_t cursor_id) : cursor_id_{cursor_id}, txn_{txn} {}

    uint32_t cursor_id() const override { return cursor_id_; };

    Task<void> open_cursor(const std::string& table_name, bool is_dup_sorted) override;

    Task<KeyValue> seek(ByteView key) override;

    Task<KeyValue> seek_exact(ByteView key) override;

    Task<KeyValue> first() override;

    Task<KeyValue> last() override;

    Task<KeyValue> next() override;

    Task<KeyValue> previous() override;

    Task<KeyValue> next_dup() override;

    Task<void> close_cursor() override;

    Task<silkworm::Bytes> seek_both(ByteView key, ByteView value) override;

    Task<KeyValue> seek_both_exact(ByteView key, ByteView value) override;

  private:
    uint32_t cursor_id_;
    datastore::kvdb::PooledCursor db_cursor_;
    mdbx::txn& txn_;
};

}  // namespace silkworm::db::kv::api
