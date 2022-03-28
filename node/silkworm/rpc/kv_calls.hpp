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

#include <tuple>

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

//! Current DB schema version.
constexpr auto kDbSchemaVersion = std::make_tuple<uint32_t, uint32_t, uint32_t>(3, 0, 0);

//! Current KV API protocol version.
constexpr auto kKvApiVersion = std::make_tuple<uint32_t, uint32_t, uint32_t>(5, 1, 0);

//! Unary RPC for Version method of 'ethbackend' gRPC protocol.
class KvVersionCall : public UnaryRpc<remote::KV::AsyncService, google::protobuf::Empty, types::VersionReply> {
  public:
    static void fill_predefined_reply();

    KvVersionCall(remote::KV::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers);

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
    TxCall(remote::KV::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers);

    void process(const remote::Cursor* request) override;
};

//! Factory specialization for Tx method.
class TxCallFactory : public CallFactory<remote::KV::AsyncService, TxCall> {
  public:
    explicit TxCallFactory(const EthereumBackEnd& backend);

  private:
    mdbx::env_managed* chaindata_env_;
};

//! Server-streaming RPC for StateChanges method of 'kv' gRPC protocol.
class StateChangesCall : public ServerStreamingRpc<remote::KV::AsyncService, remote::StateChangeRequest, remote::StateChangeBatch> {
  public:
    StateChangesCall(remote::KV::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers);

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

    void register_kv_request_calls(remote::KV::AsyncService* async_service, grpc::ServerCompletionQueue* queue);

  private:
    KvVersionCallFactory kv_version_factory_;
    TxCallFactory tx_factory_;
    StateChangesCallFactory state_changes_factory_;
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_KV_FACTORIES_HPP_
