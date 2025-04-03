// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/infra/grpc/server/server_settings.hpp>
#include <silkworm/sentry/api/router/service_router.hpp>

namespace silkworm::sentry::grpc::server {

class ServerImpl;

class Server final {
  public:
    explicit Server(
        const silkworm::rpc::ServerSettings& config,
        api::router::ServiceRouter router);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    Task<void> async_run();

  private:
    std::unique_ptr<ServerImpl> p_impl_;
};

}  // namespace silkworm::sentry::grpc::server
