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

#include <silkworm/core/chain/config.hpp>
#include <silkworm/db/kv/grpc/server/kv_server.hpp>
#include <silkworm/node/backend/ethereum_backend.hpp>
#include <silkworm/node/remote/ethbackend/grpc/server/backend_server.hpp>

namespace silkworm::node {

class BackEndKvServer : public ethbackend::grpc::server::BackEndServer, public db::kv::grpc::server::KvServer {
  public:
    BackEndKvServer(const rpc::ServerSettings& settings, const EthereumBackEnd& backend);

    BackEndKvServer(const BackEndKvServer&) = delete;
    BackEndKvServer& operator=(const BackEndKvServer&) = delete;

  protected:
    void register_async_services(::grpc::ServerBuilder& builder) override;
    void register_request_calls() override;
};

}  // namespace silkworm::node
