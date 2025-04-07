// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <exception>
#include <map>
#include <memory>
#include <optional>
#include <tuple>
#include <utility>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <grpcpp/grpcpp.h>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/infra/grpc/server/call.hpp>
#include <silkworm/infra/grpc/server/server.hpp>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>

#include "../../api/direct_service.hpp"
#include "state_change_collection.hpp"

// KV API protocol versions
// 5.1.0 - first issue

namespace silkworm::db::kv::grpc::server {

using namespace silkworm::datastore::kvdb;

api::Version higher_version_ignoring_patch(api::Version lhs, api::Version rhs);

//! Current DB schema version.
inline constexpr api::Version kDbSchemaVersion{3, 0, 0};

//! The max life duration for MDBX transactions (long-lived transactions are discouraged).
inline constexpr std::chrono::milliseconds kMaxTxDuration{60'000};

//! The max number of opened cursors for each remote transaction (arbitrary limit on this KV implementation).
inline constexpr size_t kMaxTxCursors = 100;

//! Unary RPC for Version method of 'ethbackend' gRPC protocol.
//! rpc Version(google.protobuf.Empty) returns (types.VersionReply);
class KvVersionCall : public rpc::server::UnaryCall<google::protobuf::Empty, types::VersionReply> {
  public:
    using Base::UnaryCall;

    static void fill_predefined_reply();

    Task<void> operator()();

  private:
    static types::VersionReply response_;
};

//! Bidirectional-streaming RPC for Tx method of 'kv' gRPC protocol.
//! rpc Tx(stream Cursor) returns (stream Pair);
class TxCall : public rpc::server::BidiStreamingCall<remote::Cursor, remote::Pair> {
  public:
    using Base::BidiStreamingCall;

    static void set_max_ttl_duration(const std::chrono::milliseconds& max_ttl_duration);

    Task<void> operator()(ROAccess chaindata);

  private:
    struct TxCursor {
        std::unique_ptr<ROCursorDupSort> cursor;
        std::string bucket_name;
    };

    struct CursorPosition {
        std::optional<std::string> current_key;
        std::optional<std::string> current_value;
    };

    void handle(const remote::Cursor* request, remote::Pair& response);

    void handle_cursor_open(const remote::Cursor* request, remote::Pair& response);

    void handle_cursor_operation(const remote::Cursor* request, remote::Pair& response);

    void handle_cursor_close(const remote::Cursor* request);

    void handle_operation(const remote::Cursor* request, ROCursorDupSort& cursor, remote::Pair& response);

    void handle_max_ttl_timer_expired(ROAccess chaindata);

    bool save_cursors(std::vector<CursorPosition>& positions);

    bool restore_cursors(std::vector<CursorPosition>& positions);

    void handle_first(ROCursorDupSort& cursor, remote::Pair& response);

    void handle_first_dup(ROCursorDupSort& cursor, remote::Pair& response);

    void handle_seek(const remote::Cursor* request, ROCursorDupSort& cursor, remote::Pair& response);

    void handle_seek_both(const remote::Cursor* request, ROCursorDupSort& cursor, remote::Pair& response);

    void handle_seek_exact(const remote::Cursor* request, ROCursorDupSort& cursor, remote::Pair& response);

    void handle_seek_both_exact(const remote::Cursor* request, ROCursorDupSort& cursor, remote::Pair& response);

    void handle_current(ROCursorDupSort& cursor, remote::Pair& response);

    void handle_last(ROCursorDupSort& cursor, remote::Pair& response);

    void handle_last_dup(ROCursorDupSort& cursor, remote::Pair& response);

    void handle_next(ROCursorDupSort& cursor, remote::Pair& response);

    void handle_next_dup(ROCursorDupSort& cursor, remote::Pair& response);

    void handle_next_no_dup(ROCursorDupSort& cursor, remote::Pair& response);

    void handle_prev(ROCursorDupSort& cursor, remote::Pair& response);

    void handle_prev_dup(ROCursorDupSort& cursor, remote::Pair& response);

    void handle_prev_no_dup(ROCursorDupSort& cursor, remote::Pair& response);

    void throw_with_internal_error(const remote::Cursor* request, const std::exception& exc);

    void throw_with_internal_error(const std::string& message);

    void throw_with_error(::grpc::Status status);

    static std::chrono::milliseconds max_ttl_duration_;
    static inline uint64_t next_tx_id_{0};

    ROTxnManaged read_only_txn_;
    std::map<uint32_t, TxCursor> cursors_;
    uint32_t last_cursor_id_{0};
};

//! Server-streaming RPC for StateChanges method of 'kv' gRPC protocol.
//! rpc StateChanges(StateChangeRequest) returns (stream StateChangeBatch);
class StateChangesCall : public rpc::server::ServerStreamingCall<remote::StateChangeRequest, remote::StateChangeBatch> {
  public:
    using Base::ServerStreamingCall;

    Task<void> operator()(StateChangeCollection* source);
};

//! Unary RPC for Snapshots method of 'kv' gRPC protocol.
//! rpc Snapshots(SnapshotsRequest) returns (SnapshotsReply);
class SnapshotsCall : public rpc::server::UnaryCall<remote::SnapshotsRequest, remote::SnapshotsReply> {
  public:
    using Base::UnaryCall;

    Task<void> operator()();
};

//! Unary RPC for HistoryGet method of 'kv' gRPC protocol.
//! rpc HistoryGet(HistoryGetReq) returns (HistoryGetReply);
class HistorySeekCall : public rpc::server::UnaryCall<remote::HistorySeekReq, remote::HistorySeekReply> {
  public:
    using Base::UnaryCall;

    Task<void> operator()();
};

//! Unary RPC for GetLatest method of 'kv' gRPC protocol.
//! rpc GetLatest(GetLatestReq) returns (GetLatestReply);
class GetLatestCall : public rpc::server::UnaryCall<remote::GetLatestReq, remote::GetLatestReply> {
  public:
    using Base::UnaryCall;

    Task<void> operator()();
};

//! Unary RPC for IndexRange method of 'kv' gRPC protocol.
//! rpc IndexRange(IndexRangeReq) returns (IndexRangeReply);
class IndexRangeCall : public rpc::server::UnaryCall<remote::IndexRangeReq, remote::IndexRangeReply> {
  public:
    using Base::UnaryCall;

    Task<void> operator()();
};

//! Unary RPC for HistoryRange method of 'kv' gRPC protocol.
//! rpc HistoryRange(HistoryRangeReq) returns (Pairs);
class HistoryRangeCall : public rpc::server::UnaryCall<remote::HistoryRangeReq, remote::Pairs> {
  public:
    using Base::UnaryCall;

    Task<void> operator()();
};

//! Unary RPC for RangeAsOf method of 'kv' gRPC protocol.
//! rpc RangeAsOf(RangeAsOfReq) returns (Pairs);
class RangeAsOfCall : public rpc::server::UnaryCall<remote::RangeAsOfReq, remote::Pairs> {
  public:
    using Base::UnaryCall;

    Task<void> operator()();
};

}  // namespace silkworm::db::kv::grpc::server
