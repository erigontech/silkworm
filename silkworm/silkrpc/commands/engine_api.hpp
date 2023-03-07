/*
   Copyright 2022 The Silkrpc Authors

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
#include <boost/asio/thread_pool.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/silkrpc/concurrency/context_pool.hpp>
#include <silkworm/silkrpc/json/types.hpp>
#include <silkworm/silkrpc/ethbackend/backend.hpp>


namespace silkrpc::http { class RequestHandler; }

namespace silkrpc::commands {

class EngineRpcApi {
public:
    explicit EngineRpcApi(std::unique_ptr<ethdb::Database>& database, std::unique_ptr<ethbackend::BackEnd>& backend): database_(database), backend_(backend) {}
    virtual ~EngineRpcApi() {}

    EngineRpcApi(const EngineRpcApi&) = delete;
    EngineRpcApi& operator=(const EngineRpcApi&) = delete;

protected:
    boost::asio::awaitable<void> handle_engine_get_payload_v1(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_engine_new_payload_v1(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_engine_forkchoice_updated_v1(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_engine_exchange_transition_configuration_v1(const nlohmann::json& request, nlohmann::json& reply);
private:
    std::unique_ptr<ethbackend::BackEnd>& backend_;
    std::unique_ptr<ethdb::Database>& database_;

    friend class silkrpc::http::RequestHandler;
};

} // namespace silkrpc::commands

