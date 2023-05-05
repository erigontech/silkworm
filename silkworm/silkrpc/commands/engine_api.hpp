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

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/silkrpc/ethdb/database.hpp>
#include <silkworm/silkrpc/ethbackend/backend.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkworm::http {
class RequestHandler;
}

namespace silkworm::rpc::commands {

using boost::asio::awaitable;

class EngineRpcApi {
  public:
    EngineRpcApi(std::unique_ptr<ethdb::Database>& database, std::unique_ptr<ethbackend::BackEnd>& backend)
        : database_{database}, backend_{backend} {}
    explicit EngineRpcApi(boost::asio::io_context& io_context)
        : EngineRpcApi(
              use_private_service<ethdb::Database>(io_context),
              use_private_service<ethbackend::BackEnd>(io_context)) {}
    virtual ~EngineRpcApi() = default;

    EngineRpcApi(const EngineRpcApi&) = delete;
    EngineRpcApi& operator=(const EngineRpcApi&) = delete;

  protected:
    awaitable<void> handle_engine_get_payload_v1(const nlohmann::json& request, nlohmann::json& reply);
    awaitable<void> handle_engine_new_payload_v1(const nlohmann::json& request, nlohmann::json& reply);
    awaitable<void> handle_engine_forkchoice_updated_v1(const nlohmann::json& request, nlohmann::json& reply);
    awaitable<void> handle_engine_exchange_transition_configuration_v1(const nlohmann::json& request, nlohmann::json& reply);

  private:
    std::unique_ptr<ethdb::Database>& database_;
    std::unique_ptr<ethbackend::BackEnd>& backend_;

    friend class silkworm::http::RequestHandler;
};

}  // namespace silkworm::rpc::commands
