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
#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/ethbackend/backend.hpp>
#include <silkworm/silkrpc/json/types.hpp>
#include <silkworm/silkrpc/types/log.hpp>

namespace silkworm::http {
class RequestHandler;
}

namespace silkworm::rpc::commands {

using boost::asio::awaitable;

class AdminRpcApi {
  public:
    explicit AdminRpcApi(std::unique_ptr<ethbackend::BackEnd>& backend) : backend_(backend) {}
    explicit AdminRpcApi(boost::asio::io_context& io_context)
        : AdminRpcApi(use_private_service<ethbackend::BackEnd>(io_context)) {}
    virtual ~AdminRpcApi() = default;

    AdminRpcApi(const AdminRpcApi&) = delete;
    AdminRpcApi& operator=(const AdminRpcApi&) = delete;

  protected:
    awaitable<void> handle_admin_node_info(const nlohmann::json& request, nlohmann::json& reply);
    awaitable<void> handle_admin_peers(const nlohmann::json& request, nlohmann::json& reply);

  private:
    std::unique_ptr<ethbackend::BackEnd>& backend_;

    friend class silkworm::http::RequestHandler;
};
}  // namespace silkworm::rpc::commands
