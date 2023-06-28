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

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/thread_pool.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/silkrpc/common/block_cache.hpp>
#include <silkworm/silkrpc/ethbackend/backend.hpp>
#include <silkworm/silkrpc/ethdb/database.hpp>
#include <silkworm/silkrpc/ethdb/kv/state_cache.hpp>
#include <silkworm/silkrpc/json/types.hpp>
#include <silkworm/silkrpc/types/log.hpp>

namespace silkworm::http {
class RequestHandler;
}

namespace silkworm::rpc::commands {

class OtsRpcApi {
  public:
    OtsRpcApi(boost::asio::io_context& io_context, boost::asio::thread_pool& workers)
        : io_context_(io_context),
          workers_{workers},
          database_(must_use_private_service<ethdb::Database>(io_context_)),
          state_cache_(must_use_shared_service<ethdb::kv::StateCache>(io_context_)),
          block_cache_(must_use_shared_service<BlockCache>(io_context_)) {}
    virtual ~OtsRpcApi() = default;

    OtsRpcApi(const OtsRpcApi&) = delete;
    OtsRpcApi& operator=(const OtsRpcApi&) = delete;

  protected:
    boost::asio::awaitable<void> handle_ots_get_api_level(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_has_code(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_get_block_details(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_get_block_details_by_hash(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_get_block_transactions(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_get_transaction_by_sender_and_nonce(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_get_contract_creator(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_trace_transaction(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_get_transaction_error(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_get_internal_operations(const nlohmann::json& request, nlohmann::json& reply);

    boost::asio::io_context& io_context_;
    boost::asio::thread_pool& workers_;
    ethdb::Database* database_;
    ethdb::kv::StateCache* state_cache_;
    BlockCache* block_cache_;
    friend class silkworm::http::RequestHandler;

  private:
    static IssuanceDetails get_issuance(const ChainConfig& chain_config, const silkworm::BlockWithHash& block);
    static intx::uint256 get_block_fees(const ChainConfig& chain_config, const silkworm::BlockWithHash& block,
                                        std::vector<Receipt>& receipts, silkworm::BlockNum block_number);
};

}  // namespace silkworm::rpc::commands
