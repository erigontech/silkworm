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

#include <silkworm/backend/rpc/sentry_client.hpp>
#include <silkworm/common/log.hpp>

namespace silkworm::rpc {

BackEndKvService::BackEndKvService(const EthereumBackEnd& backend)
    : BackEndService(backend), KvService(backend) {
}

BackEndKvServer::BackEndKvServer(const ServerConfig& srv_config, const EthereumBackEnd& backend)
    : Server(srv_config), backend_(backend) {
    backend_kv_services_.reserve(srv_config.num_contexts());
    for (std::size_t i{0}; i < srv_config.num_contexts(); i++) {
        backend_kv_services_.emplace_back(std::make_unique<BackEndKvService>(backend));
    }
    SILK_INFO << "BackEndKvServer created listening on: " << srv_config.address_uri();
}

// Register the gRPC services: they must exist for the lifetime of the server built by builder.
void BackEndKvServer::register_async_services(grpc::ServerBuilder& builder) {
    builder.RegisterService(&backend_async_service_);
    builder.RegisterService(&kv_async_service_);
}

/// Start server-side RPC requests as required by gRPC async model: one RPC per type is requested in advance.
void BackEndKvServer::register_request_calls() {
    // Start all server-side RPC requests for each available server context
    for (auto& backend_kv_svc : backend_kv_services_) {
        const auto& server_context = next_context();

        // Complete the service initialization
        RemoteSentryClientFactory sentry_factory{*server_context.client_grpc_context()};
        for (const auto& sentry_address : backend_.sentry_addresses()) {
            backend_kv_svc->add_sentry(sentry_factory.make_sentry_client(sentry_address));
        }

        // Register initial requested calls for ETHBACKEND and KV services
        BackEndKvService::register_backend_request_calls(server_context, &backend_async_service_);
        BackEndKvService::register_kv_request_calls(server_context, &kv_async_service_);
    }
}

}  // namespace silkworm::rpc
