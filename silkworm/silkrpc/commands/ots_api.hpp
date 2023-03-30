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
#include <vector>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/concurrency/context_pool.hpp>
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
    explicit OtsRpcApi(Context& context) : database_(context.database()), state_cache_(context.state_cache()) {}
    virtual ~OtsRpcApi() = default;

    OtsRpcApi(const OtsRpcApi&) = delete;
    OtsRpcApi& operator=(const OtsRpcApi&) = delete;

  protected:
    boost::asio::awaitable<void> handle_ots_get_api_level(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_has_code(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_getBlockDetails(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_getBlockDetailsByHash(const nlohmann::json& request, nlohmann::json& reply);

    std::unique_ptr<ethdb::Database>& database_;
    std::shared_ptr<ethdb::kv::StateCache>& state_cache_;
    friend class silkworm::http::RequestHandler;

  private:
    static IssuanceDetails get_issuance(const ChainConfig& chain_config, const silkworm::BlockWithHash& block);
    static intx::uint256 get_block_fees(const ChainConfig& chain_config, const silkworm::BlockWithHash& block, std::vector<Receipt>& receipts, silkworm::BlockNum block_number);
};

}  // namespace silkworm::rpc::commands
