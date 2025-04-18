// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/db/kv/api/client.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/core/block_reader.hpp>
#include <silkworm/rpc/ethbackend/backend.hpp>
#include <silkworm/rpc/json/stream.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc::json_rpc {
class RequestHandler;
}

namespace silkworm::rpc::commands {

class DebugRpcApi {
  public:
    DebugRpcApi(boost::asio::io_context& ioc, WorkerPool& workers)
        : ioc_{ioc},
          block_cache_{must_use_shared_service<BlockCache>(ioc_)},
          state_cache_{must_use_shared_service<db::kv::api::StateCache>(ioc_)},
          database_{must_use_private_service<db::kv::api::Client>(ioc_)->service()},
          workers_{workers},
          backend_{must_use_private_service<ethbackend::BackEnd>(ioc_)} {}
    virtual ~DebugRpcApi() = default;

    DebugRpcApi(const DebugRpcApi&) = delete;
    DebugRpcApi& operator=(const DebugRpcApi&) = delete;
    DebugRpcApi(DebugRpcApi&&) = default;

  protected:
    Task<void> handle_debug_account_range(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_debug_get_modified_accounts_by_number(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_debug_storage_range_at(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_debug_account_at(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_debug_get_modified_accounts_by_hash(const nlohmann::json& request, nlohmann::json& reply);

    Task<void> handle_debug_trace_transaction(const nlohmann::json& request, json::Stream& stream);
    Task<void> handle_debug_trace_call(const nlohmann::json& request, json::Stream& stream);
    Task<void> handle_debug_trace_call_many(const nlohmann::json& request, json::Stream& stream);
    Task<void> handle_debug_trace_block_by_number(const nlohmann::json& request, json::Stream& stream);
    Task<void> handle_debug_trace_block_by_hash(const nlohmann::json& request, json::Stream& stream);

    Task<void> handle_debug_get_raw_block(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_debug_get_raw_header(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_debug_get_raw_transaction(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_debug_get_raw_receipts(const nlohmann::json& request, nlohmann::json& reply);

  private:
    boost::asio::io_context& ioc_;
    BlockCache* block_cache_;
    db::kv::api::StateCache* state_cache_;
    std::shared_ptr<db::kv::api::Service> database_;
    WorkerPool& workers_;
    ethbackend::BackEnd* backend_;

    friend class silkworm::rpc::json_rpc::RequestHandler;
};

Task<std::set<evmc::address>> get_modified_accounts(db::kv::api::Transaction& tx, BlockNum start_block_num, BlockNum end_block_num, BlockNum latest_block_num);

}  // namespace silkworm::rpc::commands
