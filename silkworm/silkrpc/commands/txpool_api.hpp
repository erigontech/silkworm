/*
   Copyright 2020 The Silkrpc Authors

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

#include <memory>
#include <set>

#include <silkworm/silkrpc/config.hpp> // NOLINT(build/include_order)

#include <boost/asio/awaitable.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/silkrpc/concurrency/context_pool.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkrpc::http { class RequestHandler; }

namespace silkrpc::commands {

class TxPoolRpcApi {
public:
    explicit TxPoolRpcApi(Context& context)
    : context_(context), database_(context.database()), tx_pool_{context.tx_pool()} {}
    virtual ~TxPoolRpcApi() {}

    TxPoolRpcApi(const TxPoolRpcApi&) = delete;
    TxPoolRpcApi& operator=(const TxPoolRpcApi&) = delete;

protected:
    boost::asio::awaitable<void> handle_txpool_status(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_txpool_content(const nlohmann::json& request, nlohmann::json& reply);

private:
    Context& context_;
    std::unique_ptr<ethdb::Database>& database_;
    std::unique_ptr<txpool::TransactionPool>& tx_pool_;

    friend class silkrpc::http::RequestHandler;
};

} // namespace silkrpc::commands

