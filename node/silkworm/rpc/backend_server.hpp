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

#include <grpcpp/grpcpp.h>
#include <remote/ethbackend.grpc.pb.h>

#include <silkworm/chain/config.hpp>
#include <silkworm/rpc/server.hpp>
#include <silkworm/rpc/service.hpp>
#include <silkworm/rpc/call.hpp>

namespace silkworm::rpc {

//! Unary RPC for Etherbase method of 'ethbackend' gRPC protocol.
using EtherbaseUnaryRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::EtherbaseRequest, remote::EtherbaseReply>;

//! Service specialization acting as factory for Etherbase RPCs.
using EtherbaseRpcService = RpcService<
    remote::ETHBACKEND::AsyncService,
    remote::EtherbaseRequest,
    remote::EtherbaseReply,
    UnaryRpc
>;

class EtherbaseService : public EtherbaseRpcService {
  public:
    explicit EtherbaseService(const ChainConfig& /*config*/)
        : EtherbaseRpcService(
            [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
            &remote::ETHBACKEND::AsyncService::RequestEtherbase
        ) {}

    void process_rpc(EtherbaseUnaryRpc& rpc, const remote::EtherbaseRequest* request);

  private:
    evmc::address etherbase_; // TODO(canepat): read from config (field not yet present)
};

//! Unary RPC for NetVersion method of 'ethbackend' gRPC protocol.
using NetVersionUnaryRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::NetVersionRequest, remote::NetVersionReply>;

//! Service specialization acting as factory for NetVersion RPCs.
using NetVersionRpcService = RpcService<
    remote::ETHBACKEND::AsyncService,
    remote::NetVersionRequest,
    remote::NetVersionReply,
    UnaryRpc
>;

class NetVersionService : public NetVersionRpcService {
  public:
    explicit NetVersionService(const ChainConfig& config)
        : NetVersionRpcService(
            [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
            &remote::ETHBACKEND::AsyncService::RequestNetVersion
        ), chain_id_(config.chain_id) {}

    void process_rpc(NetVersionUnaryRpc& rpc, const remote::NetVersionRequest* request);

  private:
    uint64_t chain_id_;
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
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_BACKEND_SERVER_HPP_
