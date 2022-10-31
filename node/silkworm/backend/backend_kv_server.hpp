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
#include <vector>

#include <remote/ethbackend.grpc.pb.h>
#include <remote/kv.grpc.pb.h>

#include <silkworm/backend/rpc/backend_calls.hpp>
#include <silkworm/backend/rpc/kv_calls.hpp>
#include <silkworm/chain/config.hpp>
#include <silkworm/rpc/server/server.hpp>

namespace silkworm::rpc {

class BackEndKvService : public BackEndService, public KvService {
  public:
    explicit BackEndKvService(const EthereumBackEnd& backend);
};

class BackEndKvServer : public Server {
  public:
    BackEndKvServer(const ServerConfig& srv_config, const EthereumBackEnd& backend);

    BackEndKvServer(const BackEndKvServer&) = delete;
    BackEndKvServer& operator=(const BackEndKvServer&) = delete;

  protected:
    void register_async_services(grpc::ServerBuilder& builder) override;
    void register_request_calls() override;

  private:
    //! The Ethereum full node service.
    const EthereumBackEnd& backend_;

    /// \warning The gRPC service must exist for the lifetime of the gRPC server it is registered on.
    remote::ETHBACKEND::AsyncService backend_async_service_;

    /// \warning The gRPC service must exist for the lifetime of the gRPC server it is registered on.
    remote::KV::AsyncService kv_async_service_;

    //! The sequence of \ref BackEndKvService instance, one for each \ref ServerContext.
    std::vector<std::unique_ptr<BackEndKvService>> backend_kv_services_;
};

}  // namespace silkworm::rpc
