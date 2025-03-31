// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/infra/grpc/server/server_settings.hpp>

#include "../../api/direct_service.hpp"

namespace silkworm::execution::grpc::server {

class ServerImpl;

class Server final {
  public:
    Server(rpc::ServerSettings settings, std::shared_ptr<api::DirectService> service);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    Task<void> async_run(std::optional<size_t> stack_size = {});

  private:
    std::unique_ptr<ServerImpl> p_impl_;
};

}  // namespace silkworm::execution::grpc::server
