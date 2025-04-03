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

class NetRpcApi {
  public:
    explicit NetRpcApi(ethbackend::BackEnd* backend) : backend_(backend) {}
    explicit NetRpcApi(boost::asio::io_context& ioc)
        : NetRpcApi(must_use_private_service<ethbackend::BackEnd>(ioc)) {}
    virtual ~NetRpcApi() = default;

    NetRpcApi(const NetRpcApi&) = delete;
    NetRpcApi& operator=(const NetRpcApi&) = delete;
    NetRpcApi(NetRpcApi&&) = default;

  protected:
    Task<void> handle_net_listening(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_net_peer_count(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_net_version(const nlohmann::json& request, nlohmann::json& reply);

  private:
    friend class silkworm::rpc::json_rpc::RequestHandler;

    ethbackend::BackEnd* backend_;
};
}  // namespace silkworm::rpc::commands
