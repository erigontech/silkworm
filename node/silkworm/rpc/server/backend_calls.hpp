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

#include <memory>
#include <set>
#include <tuple>
#include <utility>
#include <vector>

#include <agrpc/asio_grpc.hpp>
#include <grpcpp/grpcpp.h>
#include <remote/ethbackend.grpc.pb.h>
#include <remote/ethbackend.pb.h>

#include <silkworm/backend/ethereum_backend.hpp>
#include <silkworm/chain/config.hpp>
#include <silkworm/rpc/client/sentry_client.hpp>
#include <silkworm/rpc/server/call.hpp>
#include <silkworm/rpc/server/call_factory.hpp>
#include <silkworm/rpc/server/server.hpp>
#include <silkworm/rpc/server/server_context_pool.hpp>

// ETHBACKEND API protocol versions
// 2.2.0 - first issue

namespace silkworm::rpc {

//! Current devp2p 'eth' protocol version in use.
constexpr uint64_t kEthDevp2pProtocolVersion = 66;

//! Current ETHBACKEND API protocol version.
constexpr auto kEthBackEndApiVersion = std::make_tuple<uint32_t, uint32_t, uint32_t>(2, 3, 0);

//! Unary RPC for Etherbase method of 'ethbackend' gRPC protocol.
class EtherbaseCall {
  public:
    using Responder = grpc::ServerAsyncResponseWriter<remote::EtherbaseReply>;

    static void fill_predefined_reply(const EthereumBackEnd& backend);

    boost::asio::awaitable<void> operator()(grpc::ServerContext& server_context, remote::EtherbaseRequest& request, Responder& writer);

  private:
    static remote::EtherbaseReply response_;
};

//! Unary RPC for NetVersion method of 'ethbackend' gRPC protocol.
class NetVersionCall {
  public:
    using Responder = grpc::ServerAsyncResponseWriter<remote::NetVersionReply>;

    static void fill_predefined_reply(const EthereumBackEnd& backend);

    boost::asio::awaitable<void> operator()(grpc::ServerContext& server_context, remote::NetVersionRequest& request, Responder& writer);

  private:
    static remote::NetVersionReply response_;
};

//! Unary RPC for NetPeerCount method of 'ethbackend' gRPC protocol.
class NetPeerCountCall {
  public:
    using Responder = grpc::ServerAsyncResponseWriter<remote::NetPeerCountReply>;

    static void add_sentry(SentryClient* sentry);
    static void remove_sentry(SentryClient* sentry);

    boost::asio::awaitable<void> operator()(grpc::ServerContext& server_context, remote::NetPeerCountRequest& request, Responder& writer);

  private:
    static std::set<SentryClient*> sentries_;
};

//! Unary RPC for Version method of 'ethbackend' gRPC protocol.
class BackEndVersionCall {
  public:
    using Responder = grpc::ServerAsyncResponseWriter<types::VersionReply>;

    static void fill_predefined_reply();

    boost::asio::awaitable<void> operator()(grpc::ServerContext& server_context, google::protobuf::Empty& request, Responder& writer);

  private:
    static types::VersionReply response_;
};

//! Unary RPC for ProtocolVersion method of 'ethbackend' gRPC protocol.
class ProtocolVersionCall {
  public:
    using Responder = grpc::ServerAsyncResponseWriter<remote::ProtocolVersionReply>;

    static void fill_predefined_reply();

    boost::asio::awaitable<void> operator()(grpc::ServerContext& server_context, remote::ProtocolVersionRequest& request, Responder& writer);

  private:
    static remote::ProtocolVersionReply response_;
};

//! Unary RPC for ClientVersion method of 'ethbackend' gRPC protocol.
class ClientVersionCall {
  public:
    using Responder = grpc::ServerAsyncResponseWriter<remote::ClientVersionReply>;

    static void fill_predefined_reply(const EthereumBackEnd& backend);

    boost::asio::awaitable<void> operator()(grpc::ServerContext& server_context, remote::ClientVersionRequest& request, Responder& writer);

  private:
    static remote::ClientVersionReply response_;
};

//! Server-streaming RPC for Subscribe method of 'ethbackend' gRPC protocol.
class SubscribeCall {
  public:
    using Responder = grpc::ServerAsyncWriter<remote::SubscribeReply>;

    boost::asio::awaitable<void> operator()(grpc::ServerContext& server_context, remote::SubscribeRequest& request, Responder& writer);
};

//! Unary RPC for NodeInfo method of 'ethbackend' gRPC protocol.
class NodeInfoCall {
  public:
    using Responder = grpc::ServerAsyncResponseWriter<remote::NodesInfoReply>;

    static void add_sentry(SentryClient* sentry);
    static void remove_sentry(SentryClient* sentry);

    boost::asio::awaitable<void> operator()(grpc::ServerContext& server_context, remote::NodesInfoRequest& request, Responder& writer);

  private:
    static std::set<SentryClient*> sentries_;
};

//! The ETHBACKEND service implementation.
struct BackEndService {
  public:
    explicit BackEndService(const EthereumBackEnd& backend);
    ~BackEndService();

    void register_backend_request_calls(const ServerContext& context, remote::ETHBACKEND::AsyncService* service);

    void add_sentry(std::unique_ptr<SentryClient>&& sentry);

  private:
    template <class RPC, class RequestHandler>
    void register_request_repeatedly(const ServerContext& context, remote::ETHBACKEND::AsyncService* service, RPC rpc, RequestHandler&& handler);

    std::vector<std::unique_ptr<SentryClient>> sentries_;
};

}  // namespace silkworm::rpc
