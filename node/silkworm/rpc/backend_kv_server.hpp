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

#include <remote/ethbackend.grpc.pb.h>
#include <remote/kv.grpc.pb.h>

#include <silkworm/chain/config.hpp>
#include <silkworm/rpc/server.hpp>
#include <silkworm/rpc/backend_services.hpp>
#include <silkworm/rpc/kv_services.hpp>

namespace silkworm::rpc {

class BackEndKvServer : public Server {
  public:
    BackEndKvServer(const ServerConfig& srv_config, const ChainConfig& chain_config);

    BackEndKvServer(const BackEndKvServer&) = delete;
    BackEndKvServer& operator=(const BackEndKvServer&) = delete;

  protected:
    void register_async_services(grpc::ServerBuilder& builder) override;
    void register_request_calls() override;

  private:
    /// \warning The gRPC service must exist for the lifetime of the gRPC server it is registered on.
    remote::ETHBACKEND::AsyncService backend_async_service_;

    /// \warning The gRPC service must exist for the lifetime of the gRPC server it is registered on.
    remote::KV::AsyncService kv_async_service_;

    /* 'ethbackend' protocol services */
    EtherbaseService etherbase_service_;
    NetVersionService net_version_service_;
    NetPeerCountService net_peer_count_service_;
    BackEndVersionService backend_version_service_;
    ProtocolVersionService protocol_version_service_;
    ClientVersionService client_version_service_;
    SubscribeService subscribe_service_;
    NodeInfoService node_info_service_;

    /* 'kv' protocol services */
    KvVersionService kv_version_service_;
    TxService tx_service_;
    StateChangesService state_changes_service_;
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_BACKEND_SERVER_HPP_
