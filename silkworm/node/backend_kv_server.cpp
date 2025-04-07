// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "backend_kv_server.hpp"

#include <silkworm/db/kv/grpc/server/kv_calls.hpp>
#include <silkworm/node/remote/ethbackend/grpc/server/backend_calls.hpp>

namespace silkworm::node {

BackEndKvServer::BackEndKvServer(const rpc::ServerSettings& settings, const EthereumBackEnd& backend)
    : Server(settings),
      BackEndServer(settings, backend),
      KvServer(settings, backend.chaindata(), backend.state_change_source()) {
}

// Register the gRPC services: they must exist for the lifetime of the server built by builder.
void BackEndKvServer::register_async_services(::grpc::ServerBuilder& builder) {
    BackEndServer::register_async_services(builder);
    KvServer::register_async_services(builder);
}

// Start server-side RPC requests as required by gRPC async model: one RPC per type is requested in advance.
void BackEndKvServer::register_request_calls() {
    BackEndServer::register_request_calls();
    KvServer::register_request_calls();
}

}  // namespace silkworm::node
