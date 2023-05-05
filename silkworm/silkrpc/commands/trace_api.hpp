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

#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/silkrpc/common/block_cache.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/ethdb/database.hpp>
#include <silkworm/silkrpc/ethdb/kv/state_cache.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
#include <silkworm/silkrpc/json/stream.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkworm::http {
class RequestHandler;
}

namespace silkworm::rpc::commands {

class TraceRpcApi {
  public:
    TraceRpcApi(boost::asio::io_context& io_context, boost::asio::thread_pool& workers)
        : io_context_(io_context),
          block_cache_{use_shared_service<BlockCache>(io_context_)},
          state_cache_{use_shared_service<ethdb::kv::StateCache>(io_context_)},
          database_{use_private_service<ethdb::Database>(io_context_)},
          workers_{workers} {}
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
    boost::asio::io_context& io_context_;
    std::shared_ptr<BlockCache>& block_cache_;
    std::shared_ptr<ethdb::kv::StateCache>& state_cache_;
    std::unique_ptr<ethdb::Database>& database_;
    boost::asio::thread_pool& workers_;

    friend class silkworm::http::RequestHandler;
};

}  // namespace silkworm::rpc::commands
