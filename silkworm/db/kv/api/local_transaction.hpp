// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <map>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/db/chain/local_chain_storage.hpp>
#include <silkworm/db/data_store.hpp>

#include "base_transaction.hpp"
#include "cursor.hpp"
#include "local_cursor.hpp"

namespace silkworm::db::kv::api {

class LocalTransaction : public BaseTransaction {
  public:
    LocalTransaction(DataStoreRef data_store, const ChainConfig& chain_config, StateCache* state_cache)
        : BaseTransaction{state_cache},
          data_store_{std::move(data_store)},
          chain_config_{chain_config},
          tx_{data_store_.chaindata.access_ro().start_ro_tx()} {}

    ~LocalTransaction() override = default;

    uint64_t tx_id() const override { return tx_id_; }
    uint64_t view_id() const override { return tx_.id(); }

    Task<void> open() override;

    Task<std::shared_ptr<Cursor>> cursor(std::string_view table) override;

    Task<std::shared_ptr<CursorDupSort>> cursor_dup_sort(std::string_view table) override;

    bool is_local() const override { return true; }
    DataStoreRef data_store() const { return data_store_; }

    std::shared_ptr<chain::ChainStorage> make_storage() override;

    Task<TxnId> first_txn_num_in_block(BlockNum block_num) override;

    Task<void> close() override;

    // rpc GetLatest(GetLatestReq) returns (GetLatestReply); w/ latest=true (ts ignored)
    Task<GetLatestResult> get_latest(GetLatestRequest request) override;

    // rpc GetLatest(GetLatestReq) returns (GetLatestReply); w/ latest=false (ts used)
    Task<GetAsOfResult> get_as_of(GetAsOfRequest request) override;

    // rpc HistorySeek(HistorySeekReq) returns (HistorySeekReply);
    Task<HistoryPointResult> history_seek(HistoryPointRequest request) override;

    // rpc IndexRange(IndexRangeReq) returns (IndexRangeReply);
    Task<TimestampStreamReply> index_range(IndexRangeRequest request) override;

    // rpc HistoryRange(HistoryRangeReq) returns (Pairs);
    Task<KeyValueStreamReply> history_range(HistoryRangeRequest request) override;

    // rpc RangeAsOf(RangeAsOfReq) returns (Pairs);
    Task<KeyValueStreamReply> range_as_of(DomainRangeRequest request) override;

  private:
    template <typename DomainGetAsOfQuery>
    auto query_domain_as_of(const datastore::EntityName domain_name, ByteView key, Timestamp ts) {
        DomainGetAsOfQuery query{
            data_store_.chaindata.domain(domain_name),
            tx_,
            data_store_.state_repository_latest,
            data_store_.state_repository_historical,
            data_store_.query_caches,
        };
        return query.exec(key, ts);
    }

    template <typename HistoryGetQuery>
    auto query_history_get(datastore::kvdb::History kvdb_entity, ByteView key, datastore::Timestamp ts) {
        HistoryGetQuery query{
            kvdb_entity,
            tx_,
            data_store_.state_repository_historical,
            data_store_.query_caches,
        };
        return query.exec(key, ts);
    }

    Task<std::shared_ptr<CursorDupSort>> get_cursor(std::string_view table, bool is_cursor_dup_sort);

    static inline uint64_t next_tx_id_{0};

    std::map<std::string, std::shared_ptr<CursorDupSort>> cursors_;
    std::map<std::string, std::shared_ptr<CursorDupSort>> dup_cursors_;

    DataStoreRef data_store_;
    const ChainConfig& chain_config_;
    uint32_t last_cursor_id_{0};
    datastore::kvdb::ROTxnManaged tx_;
    uint64_t tx_id_{++next_tx_id_};
};

}  // namespace silkworm::db::kv::api
