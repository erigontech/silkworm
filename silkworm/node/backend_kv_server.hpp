// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
