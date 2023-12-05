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

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/rpc/core/rawdb/accessors.hpp>
#include <silkworm/rpc/ethbackend/backend.hpp>
#include <silkworm/rpc/ethdb/database.hpp>
#include <silkworm/rpc/ethdb/kv/state_cache.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::http {
class RequestHandler;
}

namespace silkworm::rpc::commands {

class ErigonRpcApi {
  public:
    explicit ErigonRpcApi(boost::asio::io_context& io_context)
        : block_cache_{must_use_shared_service<BlockCache>(io_context)},
          database_{must_use_private_service<ethdb::Database>(io_context)},
          backend_{must_use_private_service<ethbackend::BackEnd>(io_context)} {}
    virtual ~ErigonRpcApi() = default;

    ErigonRpcApi(const ErigonRpcApi&) = delete;
    ErigonRpcApi& operator=(const ErigonRpcApi&) = delete;

  protected:
    Task<void> handle_erigon_block_number(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_cache_check(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_get_balance_changes_in_block(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_get_block_by_timestamp(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_get_block_receipts_by_block_hash(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_get_header_by_hash(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_get_header_by_number(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_get_latest_logs(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_get_logs_by_hash(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_forks(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_watch_the_burn(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_cumulative_chain_traffic(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_erigon_node_info(const nlohmann::json& request, nlohmann::json& reply);

  private:
    BlockCache* block_cache_;
    ethdb::Database* database_;
    ethbackend::BackEnd* backend_;

    friend class silkworm::http::RequestHandler;
};

}  // namespace silkworm::rpc::commands
