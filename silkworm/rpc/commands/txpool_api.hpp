// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/rpc/txpool/transaction_pool.hpp>

namespace silkworm::rpc::json_rpc {
class RequestHandler;
}

namespace silkworm::rpc::commands {

class TxPoolRpcApi {
  public:
    explicit TxPoolRpcApi(boost::asio::io_context& ioc)
        : tx_pool_{must_use_private_service<txpool::TransactionPool>(ioc)} {}
    virtual ~TxPoolRpcApi() = default;

    TxPoolRpcApi(const TxPoolRpcApi&) = delete;
    TxPoolRpcApi& operator=(const TxPoolRpcApi&) = delete;
    TxPoolRpcApi(TxPoolRpcApi&&) = default;

  protected:
    Task<void> handle_txpool_status(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_txpool_content(const nlohmann::json& request, nlohmann::json& reply);

  private:
    txpool::TransactionPool* tx_pool_;

    friend class silkworm::rpc::json_rpc::RequestHandler;
};

}  // namespace silkworm::rpc::commands
