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

#include <memory>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/silkrpc/concurrency/context_pool.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/ethdb/database.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
#include <silkworm/silkrpc/json/stream.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkrpc::http {
class RequestHandler;
}

namespace silkrpc::commands {

class TraceRpcApi {
  public:
    explicit TraceRpcApi(Context& context, boost::asio::thread_pool& workers)
        : context_(context), database_(context.database()), tx_pool_{context.tx_pool()}, workers_{workers} {}
    virtual ~TraceRpcApi() = default;

    TraceRpcApi(const TraceRpcApi&) = delete;
    TraceRpcApi& operator=(const TraceRpcApi&) = delete;

  protected:
    boost::asio::awaitable<void> handle_trace_call(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_trace_call_many(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_trace_raw_transaction(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_trace_replay_block_transactions(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_trace_replay_transaction(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_trace_block(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_trace_get(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_trace_transaction(const nlohmann::json& request, nlohmann::json& reply);

    boost::asio::awaitable<void> handle_trace_filter(const nlohmann::json& request, json::Stream& stream);

  private:
    Context& context_;
    std::unique_ptr<ethdb::Database>& database_;
    std::unique_ptr<txpool::TransactionPool>& tx_pool_;
    boost::asio::thread_pool& workers_;

    friend class silkrpc::http::RequestHandler;
};

}  // namespace silkrpc::commands
