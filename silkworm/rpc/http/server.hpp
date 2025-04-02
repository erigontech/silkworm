// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>
#include <tuple>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/rpc/commands/rpc_api_table.hpp>
#include <silkworm/rpc/common/interface_log.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/transport/request_handler.hpp>

namespace silkworm::rpc::http {

//! The top-level class of the HTTP server.
class Server {
  public:
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Construct the server to listen on the specified local TCP end-point
    Server(std::string_view end_point,
           RequestHandlerFactory&& handler_factory,
           boost::asio::io_context& ioc,
           WorkerPool& workers,
           std::vector<std::string> allowed_origins,
           std::optional<std::string> jwt_secret,
           bool use_websocket,
           bool ws_compression,
           bool http_compression,
           bool erigon_json_rpc_compatibility);

    void start();

  private:
    static std::tuple<std::string_view, std::string_view> parse_endpoint(std::string_view tcp_end_point);

    Task<void> run();

    //! The factory of RPC request handlers
    RequestHandlerFactory handler_factory_;

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

    //! Flag indicating if HTTP protocol compression will be used
    bool http_compression_;

    //! The configured workers
    WorkerPool& workers_;

    //! Flag indicating if JSON-RPC compatibility with Erigon is enabled or not
    bool erigon_json_rpc_compatibility_;
};

}  // namespace silkworm::rpc::http
