// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <map>
#include <memory>
#include <string>
#include <type_traits>

#include <silkworm/infra/concurrency/task.hpp>

#include <agrpc/client_rpc.hpp>
#include <agrpc/grpc_context.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/db/chain/providers.hpp>
#include <silkworm/db/kv/api/base_transaction.hpp>
#include <silkworm/db/kv/api/cursor.hpp>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>

#include "remote_cursor.hpp"
#include "rpc.hpp"

namespace silkworm::db::kv::grpc::client {

class RemoteTransaction : public api::BaseTransaction {
  public:
    RemoteTransaction(::remote::KV::StubInterface& stub,
                      agrpc::GrpcContext& grpc_context,
                      api::StateCache* state_cache,
                      chain::Providers providers);
    ~RemoteTransaction() override = default;

    uint64_t tx_id() const override { return tx_id_; }
    uint64_t view_id() const override { return view_id_; }

    Task<void> open() override;

    Task<std::shared_ptr<api::Cursor>> cursor(const std::string& table) override;

    Task<std::shared_ptr<api::CursorDupSort>> cursor_dup_sort(const std::string& table) override;

    std::shared_ptr<chain::ChainStorage> make_storage() override;

    Task<TxnId> first_txn_num_in_block(BlockNum block_num) override;

    Task<void> close() override;

    // rpc GetLatest(GetLatestReq) returns (GetLatestReply); w/ latest=true (ts ignored)
    Task<api::GetLatestResult> get_latest(api::GetLatestRequest request) override;

    // rpc GetLatest(GetLatestReq) returns (GetLatestReply); w/ latest=false (ts used)
    Task<api::GetAsOfResult> get_as_of(api::GetAsOfRequest request) override;

    // rpc HistorySeek(HistorySeekReq) returns (HistorySeekReply);
    Task<api::HistoryPointResult> history_seek(api::HistoryPointRequest request) override;

    // rpc IndexRange(IndexRangeReq) returns (IndexRangeReply);
    Task<api::PaginatedTimestamps> index_range(api::IndexRangeRequest request) override;

    // rpc HistoryRange(HistoryRangeReq) returns (Pairs);
    Task<api::PaginatedKeysValues> history_range(api::HistoryRangeRequest request) override;

    // rpc RangeAsOf(RangeAsOfReq) returns (Pairs);
    Task<api::PaginatedKeysValues> range_as_of(api::DomainRangeRequest request) override;

  private:
    Task<std::shared_ptr<api::CursorDupSort>> get_cursor(const std::string& table, bool is_cursor_dup_sort);

    chain::Providers providers_;
    std::map<std::string, std::shared_ptr<api::CursorDupSort>> cursors_;
    std::map<std::string, std::shared_ptr<api::CursorDupSort>> dup_cursors_;
    ::remote::KV::StubInterface& stub_;
    agrpc::GrpcContext& grpc_context_;
    //! The wrapped Tx RPC client provided by agrpc
    TxRpc tx_rpc_;
    //! Flag indicating if agrpc::ClientRPC<>::start has been called on Tx RPC or not. This is necessary to avoid
    //! a crash in agrpc if you call agrpc::ClientRPC<>::finish before calling agrpc::ClientRPC<>::start
    bool start_called_{false};
    uint64_t tx_id_{0};
    uint64_t view_id_{0};
};

}  // namespace silkworm::db::kv::grpc::client
