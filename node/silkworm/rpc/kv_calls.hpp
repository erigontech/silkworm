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

#ifndef SILKWORM_RPC_KV_FACTORIES_HPP_
#define SILKWORM_RPC_KV_FACTORIES_HPP_

#include <exception>
#include <map>
#include <tuple>
#include <vector>

#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <grpcpp/grpcpp.h>
#include <remote/kv.grpc.pb.h>

#include <silkworm/backend/ethereum_backend.hpp>
#include <silkworm/chain/config.hpp>
#include <silkworm/db/mdbx.hpp>
#include <silkworm/rpc/call.hpp>
#include <silkworm/rpc/call_factory.hpp>
#include <silkworm/rpc/server.hpp>

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
constexpr boost::posix_time::milliseconds kMaxTxDuration{60'000};

//! The max number of opened cursors for each remote transaction (arbitrary limit on this KV implementation).
constexpr std::size_t kMaxTxCursors{100};

//! Unary RPC for Version method of 'ethbackend' gRPC protocol.
class KvVersionCall : public UnaryRpc<remote::KV::AsyncService, google::protobuf::Empty, types::VersionReply> {
  public:
    static void fill_predefined_reply();

    KvVersionCall(boost::asio::io_context& scheduler, remote::KV::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers);

    void process(const google::protobuf::Empty* request) override;

  private:
    static types::VersionReply response_;
};

//! Factory specialization for Version method.
class KvVersionCallFactory : public CallFactory<remote::KV::AsyncService, KvVersionCall> {
  public:
    explicit KvVersionCallFactory();
};

//! Bidirectional-streaming RPC for Tx method of 'kv' gRPC protocol.
class TxCall : public BidirectionalStreamingRpc<remote::KV::AsyncService, remote::Cursor, remote::Pair> {
  public:
    static void set_chaindata_env(mdbx::env* chaindata_env);
    static void set_max_ttl_duration(const boost::posix_time::milliseconds& max_ttl_duration);

    TxCall(boost::asio::io_context& scheduler, remote::KV::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers);

    void start() override;

    void process(const remote::Cursor* request) override;

    void end() override;

  private:
    struct TxCursor {
        db::Cursor cursor;
        std::string bucket_name;
    };

    struct CursorPosition {
        std::string current_key;
        std::string current_value;
    };

    void handle_cursor_open(const remote::Cursor* request);

    void handle_cursor_operation(const remote::Cursor* request);

    void handle_cursor_close(const remote::Cursor* request);

    void handle_operation(const remote::Cursor* request, db::Cursor& cursor);

    void handle_max_ttl_timer_expired(const boost::system::error_code& ec);

    bool save_cursors(std::vector<CursorPosition>& positions);

    bool restore_cursors(std::vector<CursorPosition>& positions);

    void handle_first(db::Cursor& cursor);

    void handle_first_dup(db::Cursor& cursor);

    void handle_seek(const remote::Cursor* request, db::Cursor& cursor);

    void handle_seek_both(const remote::Cursor* request, db::Cursor& cursor);

    void handle_seek_exact(const remote::Cursor* request, db::Cursor& cursor);

    void handle_seek_both_exact(const remote::Cursor* request, db::Cursor& cursor);

    void handle_current(db::Cursor& cursor);

    void handle_last(db::Cursor& cursor);

    void handle_last_dup(db::Cursor& cursor);

    void handle_next(db::Cursor& cursor);

    void handle_next_dup(db::Cursor& cursor);

    void handle_next_no_dup(db::Cursor& cursor);

    void handle_prev(db::Cursor& cursor);

    void handle_prev_dup(db::Cursor& cursor);

    void handle_prev_no_dup(db::Cursor& cursor);

    void close_with_internal_error(const remote::Cursor* request, const std::exception& exc);

    void close_with_internal_error(const std::string& error_message);

    static mdbx::env* chaindata_env_;
    static boost::posix_time::milliseconds max_ttl_duration_;

    mdbx::txn_managed read_only_txn_;
    boost::asio::deadline_timer max_ttl_timer_;
    std::map<uint32_t, TxCursor> cursors_;
    uint32_t last_cursor_id_{0};
};

//! Factory specialization for Tx method.
class TxCallFactory : public CallFactory<remote::KV::AsyncService, TxCall> {
  public:
    explicit TxCallFactory(const EthereumBackEnd& backend);
};

//! Server-streaming RPC for StateChanges method of 'kv' gRPC protocol.
class StateChangesCall : public ServerStreamingRpc<remote::KV::AsyncService, remote::StateChangeRequest, remote::StateChangeBatch> {
  public:
    StateChangesCall(boost::asio::io_context& scheduler, remote::KV::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers);

    void process(const remote::StateChangeRequest* request) override;
};

//! Factory specialization for StateChanges method.
class StateChangesCallFactory : public CallFactory<remote::KV::AsyncService, StateChangesCall> {
  public:
    explicit StateChangesCallFactory();
};

//! The KV service implementation.
class KvService {
  public:
    explicit KvService(const EthereumBackEnd& backend);

    void register_kv_request_calls(boost::asio::io_context& scheduler, remote::KV::AsyncService* async_service, grpc::ServerCompletionQueue* queue);

  private:
    KvVersionCallFactory kv_version_factory_;
    TxCallFactory tx_factory_;
    StateChangesCallFactory state_changes_factory_;
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_KV_FACTORIES_HPP_
