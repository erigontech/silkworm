// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <set>
#include <tuple>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <agrpc/asio_grpc.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/infra/grpc/server/call.hpp>
#include <silkworm/infra/grpc/server/server.hpp>
#include <silkworm/infra/grpc/server/server_context_pool.hpp>
#include <silkworm/interfaces/remote/ethbackend.grpc.pb.h>
#include <silkworm/interfaces/remote/ethbackend.pb.h>
#include <silkworm/node/backend/ethereum_backend.hpp>

// ETHBACKEND API protocol versions
// 2.2.0 - first issue

namespace silkworm::ethbackend::grpc::server {

//! Current devp2p 'eth' protocol version in use.
inline constexpr uint64_t kEthDevp2pProtocolVersion = 66;

//! Current ETHBACKEND API protocol version.
inline constexpr auto kEthBackEndApiVersion = std::make_tuple<uint32_t, uint32_t, uint32_t>(2, 3, 0);

//! Unary RPC for Etherbase method of 'ethbackend' gRPC protocol.
class EtherbaseCall : public rpc::server::UnaryCall<remote::EtherbaseRequest, remote::EtherbaseReply> {
  public:
    using Base::UnaryCall;

    static void fill_predefined_reply(const EthereumBackEnd& backend);

    Task<void> operator()(const EthereumBackEnd& backend);

  private:
    static remote::EtherbaseReply response_;
};

//! Unary RPC for NetVersion method of 'ethbackend' gRPC protocol.
class NetVersionCall : public rpc::server::UnaryCall<remote::NetVersionRequest, remote::NetVersionReply> {
  public:
    using Base::UnaryCall;

    static void fill_predefined_reply(const EthereumBackEnd& backend);

    Task<void> operator()(const EthereumBackEnd& backend);

  private:
    static remote::NetVersionReply response_;
};

//! Unary RPC for NetPeerCount method of 'ethbackend' gRPC protocol.
class NetPeerCountCall : public rpc::server::UnaryCall<remote::NetPeerCountRequest, remote::NetPeerCountReply> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(const EthereumBackEnd& backend);
};

//! Unary RPC for Version method of 'ethbackend' gRPC protocol.
class BackEndVersionCall : public rpc::server::UnaryCall<google::protobuf::Empty, types::VersionReply> {
  public:
    using Base::UnaryCall;

    static void fill_predefined_reply();

    Task<void> operator()(const EthereumBackEnd& backend);

  private:
    static types::VersionReply response_;
};

//! Unary RPC for ProtocolVersion method of 'ethbackend' gRPC protocol.
class ProtocolVersionCall : public rpc::server::UnaryCall<remote::ProtocolVersionRequest, remote::ProtocolVersionReply> {
  public:
    using Base::UnaryCall;

    static void fill_predefined_reply();

    Task<void> operator()(const EthereumBackEnd& backend);

  private:
    static remote::ProtocolVersionReply response_;
};

//! Unary RPC for ClientVersion method of 'ethbackend' gRPC protocol.
class ClientVersionCall : public rpc::server::UnaryCall<remote::ClientVersionRequest, remote::ClientVersionReply> {
  public:
    using Base::UnaryCall;

    static void fill_predefined_reply(const EthereumBackEnd& backend);

    Task<void> operator()(const EthereumBackEnd& backend);

  private:
    static remote::ClientVersionReply response_;
};

//! Server-streaming RPC for Subscribe method of 'ethbackend' gRPC protocol.
class SubscribeCall : public rpc::server::ServerStreamingCall<remote::SubscribeRequest, remote::SubscribeReply> {
  public:
    using Base::ServerStreamingCall;

    Task<void> operator()(const EthereumBackEnd& backend);
};

//! Unary RPC for NodeInfo method of 'ethbackend' gRPC protocol.
class NodeInfoCall : public rpc::server::UnaryCall<remote::NodesInfoRequest, remote::NodesInfoReply> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(const EthereumBackEnd& backend);
};

}  // namespace silkworm::ethbackend::grpc::server
