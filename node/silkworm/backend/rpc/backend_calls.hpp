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
#include <utility>  // for std::exchange in Boost 1.78, fixed in Boost 1.79
#include <vector>

#include <agrpc/asio_grpc.hpp>
#include <grpcpp/grpcpp.h>
#include <remote/ethbackend.grpc.pb.h>
#include <remote/ethbackend.pb.h>

#include <silkworm/backend/ethereum_backend.hpp>
#include <silkworm/backend/rpc/sentry_client.hpp>
#include <silkworm/chain/config.hpp>
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
class EtherbaseCall : public server::UnaryCall<remote::EtherbaseRequest, remote::EtherbaseReply> {
  public:
    using Base::UnaryCall;

    static void fill_predefined_reply(const EthereumBackEnd& backend);

    boost::asio::awaitable<void> operator()();

  private:
    static remote::EtherbaseReply response_;
};

//! Unary RPC for NetVersion method of 'ethbackend' gRPC protocol.
class NetVersionCall : public server::UnaryCall<remote::NetVersionRequest, remote::NetVersionReply> {
  public:
    using Base::UnaryCall;

    static void fill_predefined_reply(const EthereumBackEnd& backend);

    boost::asio::awaitable<void> operator()();

  private:
    static remote::NetVersionReply response_;
};

//! Unary RPC for NetPeerCount method of 'ethbackend' gRPC protocol.
class NetPeerCountCall : public server::UnaryCall<remote::NetPeerCountRequest, remote::NetPeerCountReply> {
  public:
    using Base::UnaryCall;

    static void add_sentry(SentryClient* sentry);
    static void remove_sentry(SentryClient* sentry);

    boost::asio::awaitable<void> operator()();

  private:
    static std::set<SentryClient*> sentries_;
};

//! Unary RPC for Version method of 'ethbackend' gRPC protocol.
class BackEndVersionCall : public server::UnaryCall<google::protobuf::Empty, types::VersionReply> {
  public:
    using Base::UnaryCall;

    static void fill_predefined_reply();

    boost::asio::awaitable<void> operator()();

  private:
    static types::VersionReply response_;
};

//! Unary RPC for ProtocolVersion method of 'ethbackend' gRPC protocol.
class ProtocolVersionCall : public server::UnaryCall<remote::ProtocolVersionRequest, remote::ProtocolVersionReply> {
  public:
    using Base::UnaryCall;

    static void fill_predefined_reply();

    boost::asio::awaitable<void> operator()();

  private:
    static remote::ProtocolVersionReply response_;
};

//! Unary RPC for ClientVersion method of 'ethbackend' gRPC protocol.
class ClientVersionCall : public server::UnaryCall<remote::ClientVersionRequest, remote::ClientVersionReply> {
  public:
    using Base::UnaryCall;

    static void fill_predefined_reply(const EthereumBackEnd& backend);

    boost::asio::awaitable<void> operator()();

  private:
    static remote::ClientVersionReply response_;
};

//! Server-streaming RPC for Subscribe method of 'ethbackend' gRPC protocol.
class SubscribeCall : public server::ServerStreamingCall<remote::SubscribeRequest, remote::SubscribeReply> {
  public:
    using Base::ServerStreamingCall;

    boost::asio::awaitable<void> operator()();
};

//! Unary RPC for NodeInfo method of 'ethbackend' gRPC protocol.
class NodeInfoCall : public server::UnaryCall<remote::NodesInfoRequest, remote::NodesInfoReply> {
  public:
    using Base::UnaryCall;

    static void add_sentry(SentryClient* sentry);
    static void remove_sentry(SentryClient* sentry);

    boost::asio::awaitable<void> operator()();

  private:
    static std::set<SentryClient*> sentries_;
};

//! The ETHBACKEND service implementation.
struct BackEndService {
  public:
    static void register_backend_request_calls(const ServerContext& context, remote::ETHBACKEND::AsyncService* service);

    explicit BackEndService(const EthereumBackEnd& backend);
    ~BackEndService();

    void add_sentry(std::unique_ptr<SentryClient>&& sentry);

  private:
    std::vector<std::unique_ptr<SentryClient>> sentries_;
};

}  // namespace silkworm::rpc
