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

#ifndef SILKWORM_RPC_BACKEND_FACTORIES_HPP_
#define SILKWORM_RPC_BACKEND_FACTORIES_HPP_

#include <memory>
#include <tuple>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <remote/ethbackend.pb.h>
#include <remote/ethbackend.grpc.pb.h>

#include <silkworm/backend/ethereum_backend.hpp>
#include <silkworm/chain/config.hpp>
#include <silkworm/rpc/factory.hpp>
#include <silkworm/rpc/server.hpp>
#include <silkworm/rpc/call.hpp>
#include <silkworm/rpc/client/sentry_client.hpp>

// ETHBACKEND API protocol versions
// 2.2.0 - first issue

namespace silkworm::rpc {

//! Current devp2p 'eth' protocol version in use.
constexpr uint64_t kEthDevp2pProtocolVersion = 66;

//! Current ETHBACKEND API protocol version.
constexpr auto kEthBackEndApiVersion = std::make_tuple<uint32_t, uint32_t, uint32_t>(2, 2, 0);

//! Unary RPC for Etherbase method of 'ethbackend' gRPC protocol.
using EtherbaseRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::EtherbaseRequest, remote::EtherbaseReply>;

//! Factory specialization for Etherbase method.
using EtherbaseRpcFactory = Factory<
    remote::ETHBACKEND::AsyncService,
    remote::EtherbaseRequest,
    remote::EtherbaseReply,
    UnaryRpc
>;

//! Implementation acting as factory for Etherbase RPCs.
class EtherbaseFactory : public EtherbaseRpcFactory {
  public:
    explicit EtherbaseFactory(const EthereumBackEnd& backend);

    void process_rpc(EtherbaseRpc& rpc, const remote::EtherbaseRequest* request);

  private:
    remote::EtherbaseReply response_;
};

//! Unary RPC for NetVersion method of 'ethbackend' gRPC protocol.
using NetVersionRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::NetVersionRequest, remote::NetVersionReply>;

//! Factory specialization for NetVersion method.
using NetVersionRpcFactory = Factory<
    remote::ETHBACKEND::AsyncService,
    remote::NetVersionRequest,
    remote::NetVersionReply,
    UnaryRpc
>;

//! Implementation acting as factory for NetVersion RPCs.
class NetVersionFactory : public NetVersionRpcFactory {
  public:
    explicit NetVersionFactory(const EthereumBackEnd& backend);

    void process_rpc(NetVersionRpc& rpc, const remote::NetVersionRequest* request);

  private:
    remote::NetVersionReply response_;
};

//! Unary RPC for NetPeerCount method of 'ethbackend' gRPC protocol.
using NetPeerCountRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::NetPeerCountRequest, remote::NetPeerCountReply>;

//! Factory specialization for NetPeerCount method.
using NetPeerCountRpcFactory = Factory<
    remote::ETHBACKEND::AsyncService,
    remote::NetPeerCountRequest,
    remote::NetPeerCountReply,
    UnaryRpc
>;

//! Implementation acting as factory for NetPeerCount RPCs.
class NetPeerCountFactory : public NetPeerCountRpcFactory {
  public:
    explicit NetPeerCountFactory(const std::vector<std::unique_ptr<SentryClient>>& sentries);

    void process_rpc(NetPeerCountRpc& rpc, const remote::NetPeerCountRequest* request);

  private:
    const std::vector<std::unique_ptr<SentryClient>>& sentries_;
};

//! Unary RPC for Version method of 'ethbackend' gRPC protocol.
using BackEndVersionRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, google::protobuf::Empty, types::VersionReply>;

//! Factory specialization for Version method.
using BackEndVersionRpcFactory = Factory<
    remote::ETHBACKEND::AsyncService,
    google::protobuf::Empty,
    types::VersionReply,
    UnaryRpc
>;

//! Implementation acting as factory for Version RPCs.
class BackEndVersionFactory : public BackEndVersionRpcFactory {
  public:
    explicit BackEndVersionFactory();

    void process_rpc(BackEndVersionRpc& rpc, const google::protobuf::Empty* request);

  private:
    types::VersionReply response_;
};

//! Unary RPC for ProtocolVersion method of 'ethbackend' gRPC protocol.
using ProtocolVersionRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::ProtocolVersionRequest, remote::ProtocolVersionReply>;

//! Factory specialization for ProtocolVersion method.
using ProtocolVersionRpcFactory = Factory<
    remote::ETHBACKEND::AsyncService,
    remote::ProtocolVersionRequest,
    remote::ProtocolVersionReply,
    UnaryRpc
>;

//! Implementation acting as factory for ProtocolVersion RPCs.
class ProtocolVersionFactory : public ProtocolVersionRpcFactory {
  public:
    explicit ProtocolVersionFactory();

    void process_rpc(ProtocolVersionRpc& rpc, const remote::ProtocolVersionRequest* request);

  private:
    remote::ProtocolVersionReply response_;
};

//! Unary RPC for ClientVersion method of 'ethbackend' gRPC protocol.
using ClientVersionRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::ClientVersionRequest, remote::ClientVersionReply>;

//! Factory specialization for ClientVersion method.
using ClientVersionRpcFactory = Factory<
    remote::ETHBACKEND::AsyncService,
    remote::ClientVersionRequest,
    remote::ClientVersionReply,
    UnaryRpc
>;

//! Implementation acting as factory for ClientVersion RPCs.
class ClientVersionFactory : public ClientVersionRpcFactory {
  public:
    explicit ClientVersionFactory(const EthereumBackEnd& backend);

    void process_rpc(ClientVersionRpc& rpc, const remote::ClientVersionRequest* request);

  private:
    remote::ClientVersionReply response_;
};

//! Server-streaming RPC for Subscribe method of 'ethbackend' gRPC protocol.
using SubscribeRpc = ServerStreamingRpc<remote::ETHBACKEND::AsyncService, remote::SubscribeRequest, remote::SubscribeReply>;

//! Factory specialization for Subscribe method.
using SubscribeRpcFactory = Factory<
    remote::ETHBACKEND::AsyncService,
    remote::SubscribeRequest,
    remote::SubscribeReply,
    ServerStreamingRpc
>;

//! Implementation acting as factory for Subscribe RPCs.
class SubscribeFactory : public SubscribeRpcFactory {
  public:
    explicit SubscribeFactory();

    void process_rpc(SubscribeRpc& rpc, const remote::SubscribeRequest* request);
};

//! Unary RPC for NodeInfo method of 'ethbackend' gRPC protocol.
using NodeInfoRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::NodesInfoRequest, remote::NodesInfoReply>;

//! Factory specialization for NodeInfo method.
using NodeInfoRpcFactory = Factory<
    remote::ETHBACKEND::AsyncService,
    remote::NodesInfoRequest,
    remote::NodesInfoReply,
    UnaryRpc
>;

//! Implementation acting as factory for NodeInfo RPCs.
class NodeInfoFactory : public NodeInfoRpcFactory {
  public:
    explicit NodeInfoFactory(const std::vector<std::unique_ptr<SentryClient>>& sentries);

    void process_rpc(NodeInfoRpc& rpc, const remote::NodesInfoRequest* request);

  private:
    const std::vector<std::unique_ptr<SentryClient>>& sentries_;
};

//! The ETHBACKEND protocol factory aggregration.
struct BackEndFactoryGroup {
    EtherbaseFactory etherbase_factory;
    NetVersionFactory net_version_factory;
    NetPeerCountFactory net_peer_count_factory;
    BackEndVersionFactory backend_version_factory;
    ProtocolVersionFactory protocol_version_factory;
    ClientVersionFactory client_version_factory;
    SubscribeFactory subscribe_factory;
    NodeInfoFactory node_info_factory;

    explicit BackEndFactoryGroup(const EthereumBackEnd& backend);

    void add_sentry(std::unique_ptr<SentryClient>&& sentry);

  private:
    std::vector<std::unique_ptr<SentryClient>> sentries_;
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_BACKEND_FACTORIES_HPP_
