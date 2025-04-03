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
#include <silkworm/rpc/ethbackend/backend.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc::json_rpc {
class RequestHandler;
}

namespace silkworm::rpc::commands {

using db::kv::api::StateCache;

class ErigonRpcApi {
  public:
    ErigonRpcApi(boost::asio::io_context& ioc, WorkerPool& workers)
        : block_cache_{must_use_shared_service<BlockCache>(ioc)},
          state_cache_{must_use_shared_service<StateCache>(ioc)},
          database_{must_use_private_service<db::kv::api::Client>(ioc)->service()},
          backend_{must_use_private_service<ethbackend::BackEnd>(ioc)},
          workers_{workers} {}
    virtual ~ErigonRpcApi() = default;

    ErigonRpcApi(const ErigonRpcApi&) = delete;
    ErigonRpcApi& operator=(const ErigonRpcApi&) = delete;
    ErigonRpcApi(ErigonRpcApi&&) = default;

  protected:
    Task<void> handle_erigon_block_num(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_cache_check(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_get_balance_changes_in_block(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_get_block_receipts_by_block_hash(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_get_header_by_hash(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_get_header_by_number(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_get_latest_logs(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_get_logs_by_hash(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_forks(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_node_info(const nlohmann::json& request, nlohmann::json& reply);

    // GLAZE
    Task<void> handle_erigon_get_block_by_timestamp(const nlohmann::json& request, std::string& reply);

  private:
    BlockCache* block_cache_;
    StateCache* state_cache_;
    std::shared_ptr<db::kv::api::Service> database_;
    ethbackend::BackEnd* backend_;
    WorkerPool& workers_;

    friend class silkworm::rpc::json_rpc::RequestHandler;
};

}  // namespace silkworm::rpc::commands
