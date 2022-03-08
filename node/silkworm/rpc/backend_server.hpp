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

#ifndef SILKWORM_RPC_BACKEND_SERVER_HPP_
#define SILKWORM_RPC_BACKEND_SERVER_HPP_

#include <tuple>

#include <grpcpp/grpcpp.h>
#include <remote/ethbackend.grpc.pb.h>

#include <silkworm/chain/config.hpp>
#include <silkworm/rpc/server.hpp>
#include <silkworm/rpc/service.hpp>
#include <silkworm/rpc/call.hpp>

// ETHBACKEND API protocol versions
// 2.2.0 - first issue

namespace silkworm::rpc {

//! Current devp2p 'eth' protocol version in use.
constexpr uint64_t kEthDevp2pProtocolVersion = 66;

//! Current ETHBACKEND API protocol version.
constexpr auto kEthBackEndApiVersion = std::make_tuple<uint32_t, uint32_t, uint32_t>(2, 2, 0);

//! Unary RPC for Etherbase method of 'ethbackend' gRPC protocol.
using EtherbaseRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::EtherbaseRequest, remote::EtherbaseReply>;

//! Service specialization for Etherbase method.
using EtherbaseRpcService = RpcService<
    remote::ETHBACKEND::AsyncService,
    remote::EtherbaseRequest,
    remote::EtherbaseReply,
    UnaryRpc
>;

//! Service implementation acting as factory for Etherbase RPCs.
class EtherbaseService : public EtherbaseRpcService {
  public:
    explicit EtherbaseService(const ChainConfig& /*config*/)
        : EtherbaseRpcService(
            [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
            &remote::ETHBACKEND::AsyncService::RequestEtherbase
        ) {}

    void process_rpc(EtherbaseRpc& rpc, const remote::EtherbaseRequest* request);

  private:
    evmc::address etherbase_; // TODO(canepat): read from config (field not yet present)
};

//! Unary RPC for NetVersion method of 'ethbackend' gRPC protocol.
using NetVersionRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::NetVersionRequest, remote::NetVersionReply>;

//! Service specialization for NetVersion method.
using NetVersionRpcService = RpcService<
    remote::ETHBACKEND::AsyncService,
    remote::NetVersionRequest,
    remote::NetVersionReply,
    UnaryRpc
>;

//! Service implementation acting as factory for NetVersion RPCs.
class NetVersionService : public NetVersionRpcService {
  public:
    explicit NetVersionService(const ChainConfig& config)
        : NetVersionRpcService(
            [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
            &remote::ETHBACKEND::AsyncService::RequestNetVersion
        ), chain_id_(config.chain_id) {}

    void process_rpc(NetVersionRpc& rpc, const remote::NetVersionRequest* request);

  private:
    uint64_t chain_id_;
};

//! Unary RPC for NetPeerCount method of 'ethbackend' gRPC protocol.
using NetPeerCountRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::NetPeerCountRequest, remote::NetPeerCountReply>;

//! Service specialization for NetPeerCount method.
using NetPeerCountRpcService = RpcService<
    remote::ETHBACKEND::AsyncService,
    remote::NetPeerCountRequest,
    remote::NetPeerCountReply,
    UnaryRpc
>;

//! Service implementation acting as factory for NetPeerCount RPCs.
class NetPeerCountService : public NetPeerCountRpcService {
  public:
    explicit NetPeerCountService()
        : NetPeerCountRpcService(
            [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
            &remote::ETHBACKEND::AsyncService::RequestNetPeerCount
        ) {}

    void process_rpc(NetPeerCountRpc& rpc, const remote::NetPeerCountRequest* request);

    // TODO(canepat): use Sentry config client list built from config (not present yet)
};

//! Unary RPC for Version method of 'ethbackend' gRPC protocol.
using VersionRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, google::protobuf::Empty, types::VersionReply>;

//! Service specialization for Version method.
using VersionRpcService = RpcService<
    remote::ETHBACKEND::AsyncService,
    google::protobuf::Empty,
    types::VersionReply,
    UnaryRpc
>;

//! Service implementation acting as factory for Version RPCs.
class VersionService : public VersionRpcService {
  public:
    explicit VersionService();

    void process_rpc(VersionRpc& rpc, const google::protobuf::Empty* request);

  private:
    types::VersionReply response_;
};

//! Unary RPC for ProtocolVersion method of 'ethbackend' gRPC protocol.
using ProtocolVersionRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::ProtocolVersionRequest, remote::ProtocolVersionReply>;

//! Service specialization for ProtocolVersion method.
using ProtocolVersionRpcService = RpcService<
    remote::ETHBACKEND::AsyncService,
    remote::ProtocolVersionRequest,
    remote::ProtocolVersionReply,
    UnaryRpc
>;

//! Service implementation acting as factory for ProtocolVersion RPCs.
class ProtocolVersionService : public ProtocolVersionRpcService {
  public:
    explicit ProtocolVersionService();

    void process_rpc(ProtocolVersionRpc& rpc, const remote::ProtocolVersionRequest* request);

  private:
    remote::ProtocolVersionReply response_;
};

//! Unary RPC for ClientVersion method of 'ethbackend' gRPC protocol.
using ClientVersionRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::ClientVersionRequest, remote::ClientVersionReply>;

//! Service specialization for ClientVersion method.
using ClientVersionRpcService = RpcService<
    remote::ETHBACKEND::AsyncService,
    remote::ClientVersionRequest,
    remote::ClientVersionReply,
    UnaryRpc
>;

//! Service implementation acting as factory for ClientVersion RPCs.
class ClientVersionService : public ClientVersionRpcService {
  public:
    explicit ClientVersionService(const ServerConfig& srv_config);

    void process_rpc(ClientVersionRpc& rpc, const remote::ClientVersionRequest* request);

  private:
    remote::ClientVersionReply response_;
};

//! Server-streaming RPC for Subscribe method of 'ethbackend' gRPC protocol.
using SubscribeRpc = ServerStreamingRpc<remote::ETHBACKEND::AsyncService, remote::SubscribeRequest, remote::SubscribeReply>;

//! Service specialization for Subscribe method.
using SubscribeRpcService = RpcService<
    remote::ETHBACKEND::AsyncService,
    remote::SubscribeRequest,
    remote::SubscribeReply,
    ServerStreamingRpc
>;

//! Service implementation acting as factory for Subscribe RPCs.
class SubscribeService : public SubscribeRpcService {
  public:
    explicit SubscribeService()
        : SubscribeRpcService(
            [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
            &remote::ETHBACKEND::AsyncService::RequestSubscribe
        ) {}

    void process_rpc(SubscribeRpc& rpc, const remote::SubscribeRequest* request);
};

//! Unary RPC for NodeInfo method of 'ethbackend' gRPC protocol.
using NodeInfoRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::NodesInfoRequest, remote::NodesInfoReply>;

//! Service specialization for NodeInfo method.
using NodeInfoRpcService = RpcService<
    remote::ETHBACKEND::AsyncService,
    remote::NodesInfoRequest,
    remote::NodesInfoReply,
    UnaryRpc
>;

//! Service implementation acting as factory for NodeInfo RPCs.
class NodeInfoService : public NodeInfoRpcService {
  public:
    explicit NodeInfoService()
        : NodeInfoRpcService(
            [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
            &remote::ETHBACKEND::AsyncService::RequestNodeInfo
        ) {}

    void process_rpc(NodeInfoRpc& rpc, const remote::NodesInfoRequest* request);
};

class BackEndServer : public Server<remote::ETHBACKEND::AsyncService> {
  public:
    BackEndServer(const ServerConfig& srv_config, const ChainConfig& chain_config);

    BackEndServer(const BackEndServer&) = delete;
    BackEndServer& operator=(const BackEndServer&) = delete;

  protected:
    void request_calls() override;

  private:
    EtherbaseService etherbase_service_;
    NetVersionService net_version_service_;
    NetPeerCountService net_peer_count_service_;
    VersionService version_service_;
    ProtocolVersionService protocol_version_service_;
    ClientVersionService client_version_service_;
    SubscribeService subscribe_service_;
    NodeInfoService node_info_service_;
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_BACKEND_SERVER_HPP_
