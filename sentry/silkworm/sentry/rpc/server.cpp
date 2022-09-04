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

#include "server.hpp"

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/server/server_config.hpp>

namespace silkworm::sentry::rpc {

using namespace silkworm::log;

Server::Server(const silkworm::rpc::ServerConfig& config)
    : silkworm::rpc::Server(config) {
    std::size_t num_contexts = config.num_contexts();
    for (std::size_t i = 0; i < num_contexts; i++) {
        services_.push_back(std::make_unique<Service>());
    }
    log::Info() << "Server created"
                << " listening on: " << config.address_uri() << ";"
                << " contexts: " << num_contexts;
}

// Register the gRPC services: they must exist for the lifetime of the server built by builder.
void Server::register_async_services(grpc::ServerBuilder& builder) {
    builder.RegisterService(&async_service_);
}

/// Start server-side RPC requests as required by gRPC async model: one RPC per type is requested in advance.
void Server::register_request_calls() {
    for (auto& service : services_) {
        const auto& context = next_context();
        const auto io_context = context.io_context();
        const auto server_queue = context.server_queue();
        service->register_request_calls(*io_context, &async_service_, server_queue);
    }
}

}  // namespace silkworm::sentry::rpc
