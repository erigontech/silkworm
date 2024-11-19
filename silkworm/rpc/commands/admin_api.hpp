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

#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/rpc/ethbackend/backend.hpp>

namespace silkworm::rpc::json_rpc {
class RequestHandler;
}

namespace silkworm::rpc::commands {

class AdminRpcApi {
  public:
    explicit AdminRpcApi(ethbackend::BackEnd* backend) : backend_(backend) {}
    explicit AdminRpcApi(boost::asio::io_context& ioc)
        : AdminRpcApi(must_use_private_service<ethbackend::BackEnd>(ioc)) {}
    virtual ~AdminRpcApi() = default;

    AdminRpcApi(const AdminRpcApi&) = delete;
    AdminRpcApi& operator=(const AdminRpcApi&) = delete;
    AdminRpcApi(AdminRpcApi&&) = default;

  protected:
    Task<void> handle_admin_node_info(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_admin_peers(const nlohmann::json& request, nlohmann::json& reply);

  private:
    ethbackend::BackEnd* backend_;

    friend class silkworm::rpc::json_rpc::RequestHandler;
};
}  // namespace silkworm::rpc::commands
