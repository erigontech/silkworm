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

#ifndef SILKWORM_RPC_KV_SERVICES_HPP_
#define SILKWORM_RPC_KV_SERVICES_HPP_

#include <tuple>

#include <grpcpp/grpcpp.h>
#include <remote/kv.grpc.pb.h>

#include <silkworm/chain/config.hpp>
#include <silkworm/rpc/server.hpp>
#include <silkworm/rpc/service.hpp>
#include <silkworm/rpc/call.hpp>

// KV API protocol versions
// 5.1.0 - first issue

namespace silkworm::rpc {

//! Current KV API protocol version.
constexpr auto kKvApiVersion = std::make_tuple<uint32_t, uint32_t, uint32_t>(5, 1, 0);

//! Unary RPC for Version method of 'ethbackend' gRPC protocol.
using KvVersionRpc = UnaryRpc<remote::KV::AsyncService, google::protobuf::Empty, types::VersionReply>;

//! Service specialization for Version method.
using KvVersionRpcService = RpcService<
    remote::KV::AsyncService,
    google::protobuf::Empty,
    types::VersionReply,
    UnaryRpc
>;

//! Service implementation acting as factory for Version RPCs.
class KvVersionService : public KvVersionRpcService {
  public:
    explicit KvVersionService();

    void process_rpc(KvVersionRpc& rpc, const google::protobuf::Empty* request);

  private:
    types::VersionReply response_;
};

//! Bidirectional-streaming RPC for Tx method of 'kv' gRPC protocol.
using TxRpc = BidirectionalStreamingRpc<remote::KV::AsyncService, remote::Cursor, remote::Pair>;

//! Service specialization for Tx method.
using TxRpcService = RpcService<
    remote::KV::AsyncService,
    remote::Cursor,
    remote::Pair,
    BidirectionalStreamingRpc
>;

//! Service implementation acting as factory for Tx RPCs.
class TxService : public TxRpcService {
  public:
    explicit TxService()
        : TxRpcService(
            [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
            &remote::KV::AsyncService::RequestTx
        ) {}

    void process_rpc(TxRpc& rpc, const remote::Cursor* request);

  private:
    void handle_request(TxRpc& rpc, const remote::Cursor* request);
};

//! Server-streaming RPC for StateChanges method of 'kv' gRPC protocol.
using StateChangesRpc = ServerStreamingRpc<remote::KV::AsyncService, remote::StateChangeRequest, remote::StateChangeBatch>;

//! Service specialization for StateChanges method.
using StateChangesRpcService = RpcService<
    remote::KV::AsyncService,
    remote::StateChangeRequest,
    remote::StateChangeBatch,
    ServerStreamingRpc
>;

//! Service implementation acting as factory for StateChanges RPCs.
class StateChangesService : public StateChangesRpcService {
  public:
    explicit StateChangesService()
        : StateChangesRpcService(
            [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
            &remote::KV::AsyncService::RequestStateChanges
        ) {}

    void process_rpc(StateChangesRpc& rpc, const remote::StateChangeRequest* request);
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_KV_SERVICES_HPP_
