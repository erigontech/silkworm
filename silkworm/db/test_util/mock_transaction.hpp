// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/db/chain/chain_storage.hpp>
#include <silkworm/db/kv/api/cursor.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/db/test_util/mock_state_cache.hpp>

namespace silkworm::db::test_util {

class MockTransaction : public kv::api::Transaction {
  public:
    kv::api::StateCache* state_cache() override { return &state_cache_; }

    MOCK_METHOD(uint64_t, tx_id, (), (const, override));
    MOCK_METHOD(uint64_t, view_id, (), (const, override));
    MOCK_METHOD((Task<void>), open, (), (override));
    MOCK_METHOD((Task<std::shared_ptr<kv::api::Cursor>>), cursor, (std::string_view), (override));
    MOCK_METHOD((Task<std::shared_ptr<kv::api::CursorDupSort>>), cursor_dup_sort, (std::string_view), (override));
    bool is_local() const override { return false; }
    MOCK_METHOD((std::shared_ptr<chain::ChainStorage>), make_storage, (), (override));
    MOCK_METHOD((Task<TxnId>), first_txn_num_in_block, (BlockNum), (override));
    MOCK_METHOD((Task<void>), close, (), (override));
    MOCK_METHOD((Task<kv::api::KeyValue>), get, (std::string_view, ByteView), (override));
    MOCK_METHOD((Task<Bytes>), get_one, (std::string_view, ByteView), (override));
    MOCK_METHOD((Task<std::optional<Bytes>>), get_both_range,
                (std::string_view, ByteView, ByteView), (override));
    MOCK_METHOD((Task<kv::api::GetLatestResult>), get_latest, (kv::api::GetLatestRequest), (override));
    MOCK_METHOD((Task<kv::api::GetAsOfResult>), get_as_of, (kv::api::GetAsOfRequest), (override));
    MOCK_METHOD((Task<kv::api::HistoryPointResult>), history_seek, (kv::api::HistoryPointRequest), (override));
    MOCK_METHOD((Task<kv::api::TimestampStreamReply>), index_range, (kv::api::IndexRangeRequest), (override));
    MOCK_METHOD((Task<kv::api::KeyValueStreamReply>), history_range, (kv::api::HistoryRangeRequest), (override));
    MOCK_METHOD((Task<kv::api::KeyValueStreamReply>), range_as_of, (kv::api::DomainRangeRequest), (override));

  private:
    MockStateCache state_cache_;
};

}  // namespace silkworm::db::test_util
