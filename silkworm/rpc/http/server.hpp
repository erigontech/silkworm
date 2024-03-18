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

#include <string>
#include <tuple>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/thread_pool.hpp>

#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/rpc/commands/rpc_api_table.hpp>
#include <silkworm/rpc/common/interface_log.hpp>
#include <silkworm/rpc/json_rpc/request_handler.hpp>

namespace silkworm::rpc::http {

//! The top-level class of the HTTP server.
class Server {
  public:
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Construct the server to listen on the specified local TCP end-point
    Server(const std::string& end_point,
           const std::string& api_spec,
           boost::asio::io_context& io_context,
           boost::asio::thread_pool& workers,
           std::vector<std::string> allowed_origins,
           std::optional<std::string> jwt_secret,
           bool use_websocket,
           bool ws_compression,
           bool http_compression,
           InterfaceLogSettings ifc_log_settings = {});

    void start();

    void stop();

  private:
    static std::tuple<std::string, std::string> parse_endpoint(const std::string& tcp_end_point);

    Task<void> run();

    //! The JSON RPC API implementation
    commands::RpcApi rpc_api_;

    //! The repository of API request handlers
    commands::RpcApiTable handler_table_;

    //! The context used to perform asynchronous operations
    boost::asio::io_context& io_context_;

    //! The acceptor used to listen for incoming TCP connections
    boost::asio::ip::tcp::acceptor acceptor_;

    //! The list of allowed origins for CORS
    std::vector<std::string> allowed_origins_;

    //! The JSON Web Token (JWT) secret for secure channel communication
    std::optional<std::string> jwt_secret_;

    //! Flag indicating if WebSocket protocol will be used instead of HTTP
    bool use_websocket_;

    //! Flag indicating if WebSocket protocol compression will be used
    bool ws_compression_;

    //! Flag indicating if Http protocol compression will be used
    bool http_compression_;

    //! The interface logging configuration
    InterfaceLogSettings ifc_log_settings_;
};

}  // namespace silkworm::rpc::http
