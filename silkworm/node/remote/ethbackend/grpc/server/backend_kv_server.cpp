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

#include "backend_kv_server.hpp"

#include <silkworm/db/remote/kv/grpc/server/kv_calls.hpp>
#include <silkworm/node/remote/ethbackend/grpc/server/backend_calls.hpp>

namespace silkworm::rpc {

BackEndKvServer::BackEndKvServer(const ServerSettings& settings, const EthereumBackEnd& backend)
    : Server(settings),
      BackEndServer(settings, backend),
      KvServer(settings, backend.chaindata_env(), backend.state_change_source()) {
}

// Register the gRPC services: they must exist for the lifetime of the server built by builder.
void BackEndKvServer::register_async_services(grpc::ServerBuilder& builder) {
    BackEndServer::register_async_services(builder);
    KvServer::register_async_services(builder);
}

// Start server-side RPC requests as required by gRPC async model: one RPC per type is requested in advance.
void BackEndKvServer::register_request_calls() {
    BackEndServer::register_request_calls();
    KvServer::register_request_calls();
}

}  // namespace silkworm::rpc
