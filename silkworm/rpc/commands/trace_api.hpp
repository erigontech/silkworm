// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/db/kv/api/client.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/json/stream.hpp>

namespace silkworm::rpc::json_rpc {
class RequestHandler;
}

namespace silkworm::rpc::commands {

class TraceRpcApi {
  public:
    TraceRpcApi(boost::asio::io_context& ioc, WorkerPool& workers)
        : ioc_{ioc},
          block_cache_{must_use_shared_service<BlockCache>(ioc_)},
          state_cache_{must_use_shared_service<db::kv::api::StateCache>(ioc_)},
          database_{must_use_private_service<db::kv::api::Client>(ioc)->service()},
          workers_{workers} {}

    virtual ~TraceRpcApi() = default;

    TraceRpcApi(const TraceRpcApi&) = delete;
    TraceRpcApi& operator=(const TraceRpcApi&) = delete;
    TraceRpcApi(TraceRpcApi&&) = default;

  protected:
    Task<void> handle_trace_call(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_trace_call_many(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_trace_raw_transaction(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_trace_replay_block_transactions(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_trace_replay_transaction(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_trace_block(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_trace_get(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_trace_transaction(const nlohmann::json& request, nlohmann::json& reply);

    Task<void> handle_trace_filter(const nlohmann::json& request, json::Stream& stream);

  private:
    boost::asio::io_context& ioc_;
    BlockCache* block_cache_;
    db::kv::api::StateCache* state_cache_;
    std::shared_ptr<db::kv::api::Service> database_;
    WorkerPool& workers_;

    friend class silkworm::rpc::json_rpc::RequestHandler;
};

}  // namespace silkworm::rpc::commands
