// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <string>
#include <string_view>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/db/chain/chain_storage.hpp>

#include "cursor.hpp"
#include "endpoint/key_value.hpp"
#include "endpoint/temporal_point.hpp"
#include "endpoint/temporal_range.hpp"

namespace silkworm::db::kv::api {

class StateCache;

class Transaction {
  public:
    using Walker = std::function<bool(Bytes&, Bytes&)>;

    Transaction() = default;

    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

    virtual ~Transaction() = default;

    virtual StateCache* state_cache() = 0;

    virtual uint64_t tx_id() const = 0;
    virtual uint64_t view_id() const = 0;

    virtual Task<void> open() = 0;

    virtual Task<std::shared_ptr<Cursor>> cursor(std::string_view table) = 0;

    virtual Task<std::shared_ptr<CursorDupSort>> cursor_dup_sort(std::string_view table) = 0;

    virtual bool is_local() const = 0;

    virtual std::shared_ptr<chain::ChainStorage> make_storage() = 0;

    virtual Task<void> close() = 0;

    virtual Task<kv::api::KeyValue> get(std::string_view table, ByteView key) = 0;

    virtual Task<Bytes> get_one(std::string_view table, ByteView key) = 0;

    virtual Task<std::optional<Bytes>> get_both_range(std::string_view table, ByteView key, ByteView subkey) = 0;

    // Temporarily here waiting for a better place
    virtual Task<TxnId> first_txn_num_in_block(BlockNum block_num) = 0;

    Task<TxnId> user_txn_id_at(BlockNum block_num, uint32_t txn_index = 0) {
        const auto base_txn_in_block = co_await first_txn_num_in_block(block_num);
        co_return base_txn_in_block + 1 + txn_index;  // + 1 for system txn in the beginning of block
    }

    /** Temporal Point Queries **/

    // rpc GetLatest(GetLatestReq) returns (GetLatestReply); w/ latest=true (ts ignored)
    virtual Task<GetLatestResult> get_latest(GetLatestRequest request) = 0;

    // rpc GetLatest(GetLatestReq) returns (GetLatestReply); w/ latest=false (ts used)
    virtual Task<GetAsOfResult> get_as_of(GetAsOfRequest request) = 0;

    // rpc HistorySeek(HistorySeekReq) returns (HistorySeekReply);
    virtual Task<HistoryPointResult> history_seek(HistoryPointRequest request) = 0;

    /** Temporal Range Queries **/

    // rpc IndexRange(IndexRangeReq) returns (IndexRangeReply);
    virtual Task<TimestampStreamReply> index_range(IndexRangeRequest request) = 0;

    // rpc HistoryRange(HistoryRangeReq) returns (Pairs);
    virtual Task<KeyValueStreamReply> history_range(HistoryRangeRequest request) = 0;

    // rpc RangeAsOf(RangeAsOfReq) returns (Pairs);
    virtual Task<KeyValueStreamReply> range_as_of(DomainRangeRequest request) = 0;
};

}  // namespace silkworm::db::kv::api
