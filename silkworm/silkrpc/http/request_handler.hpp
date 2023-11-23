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

#include <silkworm/silkrpc/commands/rpc_api.hpp>
#include <silkworm/silkrpc/commands/rpc_api_table.hpp>
#include <silkworm/silkrpc/http/reply.hpp>
#include <silkworm/silkrpc/http/request.hpp>

namespace silkworm::rpc::http {

class RequestHandler {
  public:
    RequestHandler(boost::asio::ip::tcp::socket& socket,
                   commands::RpcApi& rpc_api,
                   const commands::RpcApiTable& rpc_api_table,
                   const std::vector<std::string>& allowed_origins,
                   std::optional<std::string> jwt_secret)
        : rpc_api_{rpc_api},
          socket_{socket},
          rpc_api_table_(rpc_api_table),
          jwt_secret_(std::move(jwt_secret)),
          allowed_origins_(allowed_origins) {}

    RequestHandler(const RequestHandler&) = delete;
    virtual ~RequestHandler() = default;
    RequestHandler& operator=(const RequestHandler&) = delete;

    Task<void> handle(const http::Request& request);

  protected:
    Task<bool> handle_request_and_create_reply(const nlohmann::json& request_json, http::Reply& reply);
    virtual Task<void> do_write(http::Reply& reply);

  private:
    using AuthorizationError = std::string;
    using AuthorizationResult = tl::expected<void, AuthorizationError>;
    AuthorizationResult is_request_authorized(const http::Request& request);
    bool is_valid_jsonrpc(const nlohmann::json& request_json);

    void set_cors(std::vector<Header>& headers);

    Task<void> handle_request(
        uint32_t request_id,
        commands::RpcApiTable::HandleMethod handler,
        const nlohmann::json& request_json,
        http::Reply& reply);
    Task<void> handle_request(
        uint32_t request_id,
        commands::RpcApiTable::HandleMethodGlaze handler,
        const nlohmann::json& request_json,
        http::Reply& reply);
    Task<void> handle_request(commands::RpcApiTable::HandleStream handler, const nlohmann::json& request_json);
    Task<void> write_headers();

    commands::RpcApi& rpc_api_;

    boost::asio::ip::tcp::socket& socket_;

    const commands::RpcApiTable& rpc_api_table_;

    const std::optional<std::string> jwt_secret_;

    const std::vector<std::string>& allowed_origins_;
};

}  // namespace silkworm::rpc::http
