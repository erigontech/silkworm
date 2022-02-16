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

#include <cstddef>
#include <memory>
#include <unordered_set>

#include <grpcpp/grpcpp.h>
#include <remote/ethbackend.grpc.pb.h>

#include <silkworm/chain/config.hpp>
#include <silkworm/rpc/server.hpp>
#include <silkworm/rpc/call.hpp>

namespace silkworm::rpc {

constexpr std::size_t kRequestsInitialCapacity = 10000;

class EtherbaseService {
    using EtherbaseUnaryRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::EtherbaseRequest, remote::EtherbaseReply>;

  public:
    explicit EtherbaseService(const ChainConfig& /*config*/) {
        requests_.reserve(kRequestsInitialCapacity);
    }

    void create_rpc(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue);
    void process_rpc(EtherbaseUnaryRpc& rpc, const remote::EtherbaseRequest* request);
    void cleanup_rpc(EtherbaseUnaryRpc& rpc, bool cancelled);

  private:
    evmc::address etherbase_; // TODO(canepat): read from config (field not yet present)
    std::unordered_set<std::unique_ptr<EtherbaseUnaryRpc>> requests_;
};

class NetVersionService {
    using NetVersionUnaryRpc = UnaryRpc<remote::ETHBACKEND::AsyncService, remote::NetVersionRequest, remote::NetVersionReply>;

  public:
    explicit NetVersionService(const ChainConfig& config) : chain_id_(config.chain_id) {
        requests_.reserve(kRequestsInitialCapacity);
    }

    void create_rpc(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue);
    void process_rpc(NetVersionUnaryRpc& rpc, const remote::NetVersionRequest* request);
    void cleanup_rpc(NetVersionUnaryRpc& rpc, bool cancelled);

  private:
    uint64_t chain_id_;
    std::unordered_set<std::unique_ptr<NetVersionUnaryRpc>> requests_;
};

class BackEndServer : public Server<remote::ETHBACKEND::AsyncService> {
  public:
    BackEndServer(const ServerConfig& srv_config, const ChainConfig& chain_config);
    virtual ~BackEndServer() {}

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
