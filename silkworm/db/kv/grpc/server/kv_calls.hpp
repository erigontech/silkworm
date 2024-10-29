/*
   Copyright 2022 The Silkworm Authors

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
#include <silkworm/db/datastore/mdbx/mdbx.hpp>
#include <silkworm/infra/grpc/server/call.hpp>
#include <silkworm/infra/grpc/server/server.hpp>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>

#include "../../api/direct_service.hpp"
#include "state_change_collection.hpp"

// KV API protocol versions
// 5.1.0 - first issue

namespace silkworm::db::kv::grpc::server {

api::Version higher_version_ignoring_patch(api::Version lhs, api::Version rhs);

//! Current DB schema version.
constexpr auto kDbSchemaVersion = api::Version{3, 0, 0};

//! The max life duration for MDBX transactions (long-lived transactions are discouraged).
constexpr std::chrono::milliseconds kMaxTxDuration{60'000};

//! The max number of opened cursors for each remote transaction (arbitrary limit on this KV implementation).
constexpr size_t kMaxTxCursors{100};

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

    Task<void> operator()(mdbx::env* chaindata_env);

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

    void handle_max_ttl_timer_expired(mdbx::env* chaindata_env);

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

    void throw_with_error(::grpc::Status&& status);

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

//! Unary RPC for DomainGet method of 'kv' gRPC protocol.
//! rpc DomainGet(DomainGetReq) returns (DomainGetReply);
class DomainGetCall : public rpc::server::UnaryCall<remote::DomainGetReq, remote::DomainGetReply> {
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

//! Unary RPC for IndexRange method of 'kv' gRPC protocol.
//! rpc HistoryRange(HistoryRangeReq) returns (Pairs);
class HistoryRangeCall : public rpc::server::UnaryCall<remote::HistoryRangeReq, remote::Pairs> {
  public:
    using Base::UnaryCall;

    Task<void> operator()();
};

//! Unary RPC for IndexRange method of 'kv' gRPC protocol.
//! rpc DomainRange(DomainRangeReq) returns (Pairs);
class DomainRangeCall : public rpc::server::UnaryCall<remote::DomainRangeReq, remote::Pairs> {
  public:
    using Base::UnaryCall;

    Task<void> operator()();
};

}  // namespace silkworm::db::kv::grpc::server
