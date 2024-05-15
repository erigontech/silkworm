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
#include <silkworm/db/mdbx/mdbx.hpp>
#include <silkworm/infra/grpc/server/call.hpp>
#include <silkworm/infra/grpc/server/server.hpp>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>
#include <silkworm/node/backend/ethereum_backend.hpp>
#include <silkworm/node/backend/state_change_collection.hpp>

// KV API protocol versions
// 5.1.0 - first issue

namespace silkworm::rpc {

using KvVersion = std::tuple<uint32_t, uint32_t, uint32_t>;

KvVersion higher_version_ignoring_patch(KvVersion lhs, KvVersion rhs);

//! Current DB schema version.
constexpr auto kDbSchemaVersion = KvVersion{3, 0, 0};

//! Current KV API protocol version.
constexpr auto kKvApiVersion = KvVersion{5, 1, 0};

//! The max life duration for MDBX transactions (long-lived transactions are discouraged).
constexpr std::chrono::milliseconds kMaxTxDuration{60'000};

//! The max number of opened cursors for each remote transaction (arbitrary limit on this KV implementation).
constexpr std::size_t kMaxTxCursors{100};

//! Unary RPC for Version method of 'ethbackend' gRPC protocol.
class KvVersionCall : public server::UnaryCall<google::protobuf::Empty, types::VersionReply> {
  public:
    using Base::UnaryCall;

    static void fill_predefined_reply();

    Task<void> operator()(const EthereumBackEnd& backend);

  private:
    static types::VersionReply response_;
};

//! Bidirectional-streaming RPC for Tx method of 'kv' gRPC protocol.
class TxCall : public server::BidiStreamingCall<remote::Cursor, remote::Pair> {
  public:
    using Base::BidiStreamingCall;

    static void set_max_ttl_duration(const std::chrono::milliseconds& max_ttl_duration);

    Task<void> operator()(const EthereumBackEnd& backend);

  private:
    struct TxCursor {
        std::unique_ptr<db::ROCursorDupSort> cursor;
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

    void handle_operation(const remote::Cursor* request, db::ROCursorDupSort& cursor, remote::Pair& response);

    void handle_max_ttl_timer_expired(const EthereumBackEnd& backend);

    bool save_cursors(std::vector<CursorPosition>& positions);

    bool restore_cursors(std::vector<CursorPosition>& positions);

    void handle_first(db::ROCursorDupSort& cursor, remote::Pair& response);

    void handle_first_dup(db::ROCursorDupSort& cursor, remote::Pair& response);

    void handle_seek(const remote::Cursor* request, db::ROCursorDupSort& cursor, remote::Pair& response);

    void handle_seek_both(const remote::Cursor* request, db::ROCursorDupSort& cursor, remote::Pair& response);

    void handle_seek_exact(const remote::Cursor* request, db::ROCursorDupSort& cursor, remote::Pair& response);

    void handle_seek_both_exact(const remote::Cursor* request, db::ROCursorDupSort& cursor, remote::Pair& response);

    void handle_current(db::ROCursorDupSort& cursor, remote::Pair& response);

    void handle_last(db::ROCursorDupSort& cursor, remote::Pair& response);

    void handle_last_dup(db::ROCursorDupSort& cursor, remote::Pair& response);

    void handle_next(db::ROCursorDupSort& cursor, remote::Pair& response);

    void handle_next_dup(db::ROCursorDupSort& cursor, remote::Pair& response);

    void handle_next_no_dup(db::ROCursorDupSort& cursor, remote::Pair& response);

    void handle_prev(db::ROCursorDupSort& cursor, remote::Pair& response);

    void handle_prev_dup(db::ROCursorDupSort& cursor, remote::Pair& response);

    void handle_prev_no_dup(db::ROCursorDupSort& cursor, remote::Pair& response);

    void throw_with_internal_error(const remote::Cursor* request, const std::exception& exc);

    void throw_with_internal_error(const std::string& message);

    void throw_with_error(grpc::Status&& status);

    static std::chrono::milliseconds max_ttl_duration_;

    db::ROTxnManaged read_only_txn_;
    std::map<uint32_t, TxCursor> cursors_;
    uint32_t last_cursor_id_{0};
};

//! Server-streaming RPC for StateChanges method of 'kv' gRPC protocol.
class StateChangesCall : public server::ServerStreamingCall<remote::StateChangeRequest, remote::StateChangeBatch> {
  public:
    using Base::ServerStreamingCall;

    Task<void> operator()(const EthereumBackEnd& backend);
};

}  // namespace silkworm::rpc
