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

namespace silkworm::rpc::json_rpc {
class RequestHandler;
}

namespace silkworm::rpc::commands {

using db::kv::api::StateCache;

class ParityRpcApi {
  public:
    explicit ParityRpcApi(boost::asio::io_context& ioc, WorkerPool& workers)
        : block_cache_{must_use_shared_service<BlockCache>(ioc)},
          state_cache_{must_use_shared_service<StateCache>(ioc)},
          database_{must_use_private_service<db::kv::api::Client>(ioc)->service()},
          backend_{must_use_private_service<ethbackend::BackEnd>(ioc)},
          workers_{workers} {}
    virtual ~ParityRpcApi() = default;

    ParityRpcApi(const ParityRpcApi&) = delete;
    ParityRpcApi& operator=(const ParityRpcApi&) = delete;
    ParityRpcApi(ParityRpcApi&&) = default;

  protected:
    Task<void> handle_parity_list_storage_keys(const nlohmann::json& request, nlohmann::json& reply);

  private:
    BlockCache* block_cache_;
    StateCache* state_cache_;
    std::shared_ptr<db::kv::api::Service> database_;
    ethbackend::BackEnd* backend_;
    WorkerPool& workers_;

    friend class silkworm::rpc::json_rpc::RequestHandler;
};

}  // namespace silkworm::rpc::commands
