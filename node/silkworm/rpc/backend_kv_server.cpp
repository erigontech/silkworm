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

#include <silkworm/common/log.hpp>

namespace silkworm::rpc {

BackEndKvServer::BackEndKvServer(const ServerConfig& srv_config, const ChainConfig& chain_config)
: Server(srv_config), etherbase_factory_{chain_config}, net_version_factory_{chain_config}, client_version_factory_{srv_config} {
    factory_groups_.reserve(srv_config.num_contexts());
    for (std::size_t i{0}; i<srv_config.num_contexts(); i++) {
        factory_groups_.emplace_back(std::make_unique<BackEndKvFactoryGroup>(srv_config, chain_config));
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
    // Start one server-side RPC request for each available server context
    for (auto& factory_group : factory_groups_) {
        const auto& server_context = next_context();
        const auto context_queue = server_context.grpc_queue.get();

        /* 'ethbackend' protocol factories */
        factory_group->etherbase_factory.create_rpc(&backend_async_service_, context_queue);
        factory_group->net_version_factory.create_rpc(&backend_async_service_, context_queue);
        factory_group->net_peer_count_factory.create_rpc(&backend_async_service_, context_queue);
        factory_group->backend_version_factory.create_rpc(&backend_async_service_, context_queue);
        factory_group->protocol_version_factory.create_rpc(&backend_async_service_, context_queue);
        factory_group->client_version_factory.create_rpc(&backend_async_service_, context_queue);
        factory_group->subscribe_factory.create_rpc(&backend_async_service_, context_queue);
        factory_group->node_info_factory.create_rpc(&backend_async_service_, context_queue);

        /* 'kv' protocol factories */
        factory_group->kv_version_factory.create_rpc(&kv_async_service_, context_queue);
        factory_group->tx_factory.create_rpc(&kv_async_service_, context_queue);
        factory_group->state_changes_factory.create_rpc(&kv_async_service_, context_queue);
    }
}

} // namespace silkworm::rpc
