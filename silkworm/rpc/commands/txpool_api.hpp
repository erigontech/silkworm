/*
   Copyright 2023 The Silkworm Authors

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
