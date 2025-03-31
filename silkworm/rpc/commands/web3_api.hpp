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

class Web3RpcApi {
  public:
    explicit Web3RpcApi(boost::asio::io_context& ioc)
        : backend_{must_use_private_service<ethbackend::BackEnd>(ioc)} {}
    virtual ~Web3RpcApi() = default;

    Web3RpcApi(const Web3RpcApi&) = delete;
    Web3RpcApi& operator=(const Web3RpcApi&) = delete;
    Web3RpcApi(Web3RpcApi&&) = default;

  protected:
    Task<void> handle_web3_client_version(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_web3_sha3(const nlohmann::json& request, nlohmann::json& reply);

  private:
    ethbackend::BackEnd* backend_;

    friend class silkworm::rpc::json_rpc::RequestHandler;
};

}  // namespace silkworm::rpc::commands
