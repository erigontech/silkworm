// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/rpc/ethbackend/backend.hpp>

namespace silkworm::rpc::json_rpc {
class RequestHandler;
}

namespace silkworm::rpc::commands {

class AdminRpcApi {
  public:
    explicit AdminRpcApi(ethbackend::BackEnd* backend) : backend_(backend) {}
    explicit AdminRpcApi(boost::asio::io_context& ioc)
        : AdminRpcApi(must_use_private_service<ethbackend::BackEnd>(ioc)) {}
    virtual ~AdminRpcApi() = default;

    AdminRpcApi(const AdminRpcApi&) = delete;
    AdminRpcApi& operator=(const AdminRpcApi&) = delete;
    AdminRpcApi(AdminRpcApi&&) = default;

  protected:
    Task<void> handle_admin_node_info(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_admin_peers(const nlohmann::json& request, nlohmann::json& reply);

  private:
    ethbackend::BackEnd* backend_;

    friend class silkworm::rpc::json_rpc::RequestHandler;
};
}  // namespace silkworm::rpc::commands
