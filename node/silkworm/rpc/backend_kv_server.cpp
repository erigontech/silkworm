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
: Server(srv_config), etherbase_service_{chain_config}, net_version_service_{chain_config}, client_version_service_{srv_config} {
    SILK_INFO << "BackEndKvServer created listening on: " << srv_config.address_uri();
}

// Register the gRPC services: they must exist for the lifetime of the server built by builder.
void BackEndKvServer::register_async_services(grpc::ServerBuilder& builder) {
    builder.RegisterService(&backend_async_service_);
    builder.RegisterService(&kv_async_service_);
}

/// Start server-side RPC requests as required by gRPC async model: one RPC per type is requested in advance.
void BackEndKvServer::register_request_calls() {
    // Start each server-side RPC request grabbing one context at a time using round-robin scheme

    /* 'ethbackend' protocol services */
    etherbase_service_.create_rpc(&backend_async_service_, next_context().grpc_queue.get());
    net_version_service_.create_rpc(&backend_async_service_, next_context().grpc_queue.get());
    net_peer_count_service_.create_rpc(&backend_async_service_, next_context().grpc_queue.get());
    backend_version_service_.create_rpc(&backend_async_service_, next_context().grpc_queue.get());
    protocol_version_service_.create_rpc(&backend_async_service_, next_context().grpc_queue.get());
    client_version_service_.create_rpc(&backend_async_service_, next_context().grpc_queue.get());
    subscribe_service_.create_rpc(&backend_async_service_, next_context().grpc_queue.get());
    node_info_service_.create_rpc(&backend_async_service_, next_context().grpc_queue.get());

    /* 'kv' protocol services */
    kv_version_service_.create_rpc(&kv_async_service_, next_context().grpc_queue.get());
    tx_service_.create_rpc(&kv_async_service_, next_context().grpc_queue.get());
    state_changes_service_.create_rpc(&kv_async_service_, next_context().grpc_queue.get());
}

} // namespace silkworm::rpc
