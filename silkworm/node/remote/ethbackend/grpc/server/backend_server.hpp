// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <vector>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/infra/grpc/server/server.hpp>
#include <silkworm/interfaces/remote/ethbackend.grpc.pb.h>
#include <silkworm/node/backend/ethereum_backend.hpp>

namespace silkworm::ethbackend::grpc::server {

class BackEndServer : public virtual rpc::Server {
  public:
    BackEndServer(const rpc::ServerSettings& settings, const EthereumBackEnd& backend);

    BackEndServer(const BackEndServer&) = delete;
    BackEndServer& operator=(const BackEndServer&) = delete;

  protected:
    void register_async_services(::grpc::ServerBuilder& builder) override;
    void register_request_calls() override;

  private:
    static void setup_backend_calls(const EthereumBackEnd& backend);
    void register_backend_request_calls(agrpc::GrpcContext* grpc_context);

    //! The Ethereum full node service.
    const EthereumBackEnd& backend_;

    //! \warning The gRPC service must exist for the lifetime of the gRPC server it is registered on.
    remote::ETHBACKEND::AsyncService backend_async_service_;
};

}  // namespace silkworm::ethbackend::grpc::server
