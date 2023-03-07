/*
    Copyright 2020-2021 The Silkrpc Authors

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

#include <silkworm/silkrpc/config.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/thread_pool.hpp>

#include <silkworm/silkrpc/concurrency/context_pool.hpp>
#include <silkworm/silkrpc/commands/rpc_api.hpp>
#include <silkworm/silkrpc/commands/rpc_api_table.hpp>
#include <silkworm/silkrpc/http/reply.hpp>
#include <silkworm/silkrpc/http/request.hpp>

namespace silkrpc::http {

class RequestHandler {
public:
    RequestHandler(Context& context, boost::asio::thread_pool& workers,
        boost::asio::ip::tcp::socket& socket, const commands::RpcApiTable& rpc_api_table,
        std::optional<std::string> jwt_secret)
        : rpc_api_{context, workers}, io_context_{*context.io_context()}, socket_{socket}, rpc_api_table_(rpc_api_table), jwt_secret_(jwt_secret)  {}

    RequestHandler(const RequestHandler&) = delete;
    RequestHandler& operator=(const RequestHandler&) = delete;

    boost::asio::awaitable<void> handle_request(const http::Request& request);

private:
    boost::asio::awaitable<std::optional<std::string>> is_request_authorized(uint32_t request_id, const http::Request& request);

    boost::asio::awaitable<void> handle_request(const nlohmann::json& request_json, http::Reply& reply);
    boost::asio::awaitable<void> handle_request(silkrpc::commands::RpcApiTable::HandleMethod handler, const nlohmann::json& request_json, http::Reply& reply);
    boost::asio::awaitable<void> handle_request(silkrpc::commands::RpcApiTable::HandleStream handler, const nlohmann::json& request_json);

    boost::asio::awaitable<void> do_write(http::Reply& reply);
    boost::asio::awaitable<void> write_headers();

    commands::RpcApi rpc_api_;
    boost::asio::io_context& io_context_;
    boost::asio::ip::tcp::socket& socket_;
    const commands::RpcApiTable& rpc_api_table_;
    const std::optional<std::string> jwt_secret_;
};

} // namespace silkrpc::http

