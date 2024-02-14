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

#include <map>
#include <memory>
#include <string>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/thread_pool.hpp>
#include <tl/expected.hpp>

#include <silkworm/rpc/commands/rpc_api.hpp>
#include <silkworm/rpc/commands/rpc_api_table.hpp>
#include <silkworm/rpc/common/channel.hpp>
#include <silkworm/rpc/common/interface_log.hpp>
#include <silkworm/rpc/json_rpc/json_rpc_validator.hpp>

namespace silkworm::rpc::http {

class RequestHandler {
  public:
    RequestHandler(Channel* channel,
                   commands::RpcApi& rpc_api,
                   const commands::RpcApiTable& rpc_api_table,
                   InterfaceLogSettings ifc_log_settings = {});
    virtual ~RequestHandler() = default;

    RequestHandler(const RequestHandler&) = delete;
    RequestHandler& operator=(const RequestHandler&) = delete;

    Task<void> handle(const std::string& request);

  protected:
    Task<bool> handle_request_and_create_reply(const nlohmann::json& request_json, std::string& response);

  private:
    JsonRpcValidationResult is_valid_jsonrpc(const nlohmann::json& request_json);

    Task<void> handle_request(
        commands::RpcApiTable::HandleMethod handler,
        const nlohmann::json& request_json,
        std::string& response);
    Task<void> handle_request(
        commands::RpcApiTable::HandleMethodGlaze handler,
        const nlohmann::json& request_json,
        std::string& response);
    Task<void> handle_request(commands::RpcApiTable::HandleStream handler, const nlohmann::json& request_json);

    Channel* channel_;

    commands::RpcApi& rpc_api_;

    const commands::RpcApiTable& rpc_api_table_;

    JsonRpcValidator json_rpc_validator_;

    std::shared_ptr<InterfaceLog> ifc_log_;
};

}  // namespace silkworm::rpc::http
