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
#include <set>
#include <tuple>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <remote/ethbackend.pb.h>
#include <remote/ethbackend.grpc.pb.h>

#include <silkworm/backend/ethereum_backend.hpp>
#include <silkworm/chain/config.hpp>
#include <silkworm/rpc/call.hpp>
#include <silkworm/rpc/call_factory.hpp>
#include <silkworm/rpc/client/sentry_client.hpp>
#include <silkworm/rpc/server.hpp>

// ETHBACKEND API protocol versions
// 2.2.0 - first issue

namespace silkworm::rpc {

//! Current devp2p 'eth' protocol version in use.
constexpr uint64_t kEthDevp2pProtocolVersion = 66;

//! Current ETHBACKEND API protocol version.
constexpr auto kEthBackEndApiVersion = std::make_tuple<uint32_t, uint32_t, uint32_t>(2, 2, 0);

//! Unary RPC for Etherbase method of 'ethbackend' gRPC protocol.
class EtherbaseCall : public UnaryRpc<remote::ETHBACKEND::AsyncService, remote::EtherbaseRequest, remote::EtherbaseReply> {
  public:
    static void fill_predefined_reply(const EthereumBackEnd& backend);

    EtherbaseCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers);

    void process(const remote::EtherbaseRequest* request) override;

  private:
    static remote::EtherbaseReply response_;
};

//! Factory specialization for Etherbase method.
class EtherbaseCallFactory : public CallFactory<remote::ETHBACKEND::AsyncService, EtherbaseCall> {
  public:
    explicit EtherbaseCallFactory(const EthereumBackEnd& backend);
};

//! Unary RPC for NetVersion method of 'ethbackend' gRPC protocol.
class NetVersionCall : public UnaryRpc<remote::ETHBACKEND::AsyncService, remote::NetVersionRequest, remote::NetVersionReply> {
  public:
    static void fill_predefined_reply(const EthereumBackEnd& backend);

    NetVersionCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers);

    void process(const remote::NetVersionRequest* request) override;

  private:
    static remote::NetVersionReply response_;
};

//! Factory specialization for NetVersion method.
class NetVersionCallFactory : public CallFactory<remote::ETHBACKEND::AsyncService, NetVersionCall> {
  public:
    explicit NetVersionCallFactory(const EthereumBackEnd& backend);
};

//! Unary RPC for NetPeerCount method of 'ethbackend' gRPC protocol.
class NetPeerCountCall : public UnaryRpc<remote::ETHBACKEND::AsyncService, remote::NetPeerCountRequest, remote::NetPeerCountReply> {
  public:
    static void add_sentry(SentryClient* sentry);
    static void remove_sentry(SentryClient* sentry);

    NetPeerCountCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers);

    void process(const remote::NetPeerCountRequest* request) override;

  private:
    static std::set<SentryClient*> sentries_;

    std::size_t expected_responses_{0};
    uint64_t total_count_{0};
    grpc::Status result_status_{grpc::Status::OK};
};

//! Factory specialization for NetPeerCount method.
class NetPeerCountCallFactory : public CallFactory<remote::ETHBACKEND::AsyncService, NetPeerCountCall> {
  public:
    explicit NetPeerCountCallFactory();
};

//! Unary RPC for Version method of 'ethbackend' gRPC protocol.
class BackEndVersionCall : public UnaryRpc<remote::ETHBACKEND::AsyncService, google::protobuf::Empty, types::VersionReply> {
  public:
    static void fill_predefined_reply();

    BackEndVersionCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers);

    void process(const google::protobuf::Empty* request) override;

  private:
    static types::VersionReply response_;
};

//! Factory specialization for Version method.
class BackEndVersionCallFactory : public CallFactory<remote::ETHBACKEND::AsyncService, BackEndVersionCall> {
  public:
    explicit BackEndVersionCallFactory();
};

//! Unary RPC for ProtocolVersion method of 'ethbackend' gRPC protocol.
class ProtocolVersionCall : public UnaryRpc<remote::ETHBACKEND::AsyncService, remote::ProtocolVersionRequest, remote::ProtocolVersionReply> {
  public:
    static void fill_predefined_reply();

    ProtocolVersionCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers);

    void process(const remote::ProtocolVersionRequest* request) override;

  private:
    static remote::ProtocolVersionReply response_;
};

//! Factory specialization for ProtocolVersion method.
class ProtocolVersionCallFactory : public CallFactory<remote::ETHBACKEND::AsyncService, ProtocolVersionCall> {
  public:
    explicit ProtocolVersionCallFactory();
};

//! Unary RPC for ClientVersion method of 'ethbackend' gRPC protocol.
class ClientVersionCall : public UnaryRpc<remote::ETHBACKEND::AsyncService, remote::ClientVersionRequest, remote::ClientVersionReply> {
  public:
    static void fill_predefined_reply(const EthereumBackEnd& backend);

    ClientVersionCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers);

    void process(const remote::ClientVersionRequest* request) override;

  private:
    static remote::ClientVersionReply response_;
};

//! Factory specialization for ClientVersion method.
class ClientVersionCallFactory : public CallFactory<remote::ETHBACKEND::AsyncService, ClientVersionCall> {
  public:
    explicit ClientVersionCallFactory(const EthereumBackEnd& backend);
};

//! Server-streaming RPC for Subscribe method of 'ethbackend' gRPC protocol.
class SubscribeCall : public ServerStreamingRpc<remote::ETHBACKEND::AsyncService, remote::SubscribeRequest, remote::SubscribeReply> {
  public:
    SubscribeCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers);

    void process(const remote::SubscribeRequest* request) override;
};

//! Factory specialization for Subscribe method.
class SubscribeCallFactory : public CallFactory<remote::ETHBACKEND::AsyncService, SubscribeCall> {
  public:
    explicit SubscribeCallFactory();
};

//! Unary RPC for NodeInfo method of 'ethbackend' gRPC protocol.
class NodeInfoCall : public UnaryRpc<remote::ETHBACKEND::AsyncService, remote::NodesInfoRequest, remote::NodesInfoReply> {
  public:
    static void add_sentry(SentryClient* sentry);
    static void remove_sentry(SentryClient* sentry);

    NodeInfoCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers);

    void process(const remote::NodesInfoRequest* request) override;

  private:
    static std::set<SentryClient*> sentries_;

    std::size_t expected_responses_{0};
    remote::NodesInfoReply response_;
    grpc::Status result_status_{grpc::Status::OK};
};

//! Factory specialization for NodeInfo method.
class NodeInfoCallFactory : public CallFactory<remote::ETHBACKEND::AsyncService, NodeInfoCall> {
  public:
    explicit NodeInfoCallFactory();
};

//! The ETHBACKEND service implementation.
struct BackEndService {
    EtherbaseCallFactory etherbase_factory;
    NetVersionCallFactory net_version_factory;
    NetPeerCountCallFactory net_peer_count_factory;
    BackEndVersionCallFactory backend_version_factory;
    ProtocolVersionCallFactory protocol_version_factory;
    ClientVersionCallFactory client_version_factory;
    SubscribeCallFactory subscribe_factory;
    NodeInfoCallFactory node_info_factory;

    explicit BackEndService(const EthereumBackEnd& backend);
    ~BackEndService();

    void add_sentry(std::unique_ptr<SentryClient>&& sentry);

  private:
    std::vector<std::unique_ptr<SentryClient>> sentries_;
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_BACKEND_FACTORIES_HPP_
