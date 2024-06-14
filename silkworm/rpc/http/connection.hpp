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

#include <array>
#include <memory>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/system/error_code.hpp>

#include <silkworm/rpc/commands/rpc_api_table.hpp>
#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/common/interface_log.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/transport/request_handler.hpp>
#include <silkworm/rpc/transport/stream_writer.hpp>
#include <silkworm/rpc/ws/connection.hpp>

namespace silkworm::rpc::http {

using RequestWithStringBody = boost::beast::http::request<boost::beast::http::string_body>;

//! Represents a single connection from a client.
class Connection : public StreamWriter {
  public:
    //! Run the asynchronous read loop for the specified connection.
    //! \note This is co_spawn-friendly because the connection lifetime is tied to the coroutine frame
    static Task<void> run_read_loop(std::shared_ptr<Connection> connection);

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    //! Construct a connection running within the given execution context.
    Connection(boost::asio::ip::tcp::socket socket,
               RequestHandlerFactory& handler_factory,
               const std::vector<std::string>& allowed_origins,
               std::optional<std::string> jwt_secret,
               bool ws_upgrade_enabled,
               bool ws_compression,
               bool http_compression,
               WorkerPool& workers);
    ~Connection() override;

    /* StreamWriter Interface */
    Task<void> open_stream() override;
    Task<void> close_stream() override;
    Task<std::size_t> write(std::string_view content, bool last) override;

  protected:
    //! Start the asynchronous read loop for the connection
    Task<void> read_loop();

    using AuthorizationError = std::string;
    using AuthorizationResult = tl::expected<void, AuthorizationError>;
    AuthorizationResult is_request_authorized(const RequestWithStringBody& req);

    Task<void> handle_request(const RequestWithStringBody& req);
    Task<void> handle_actual_request(const RequestWithStringBody& req);
    Task<void> handle_preflight(const RequestWithStringBody& req);

    bool is_origin_allowed(const std::vector<std::string>& allowed_origins, const std::string& origin);
    bool is_method_allowed(boost::beast::http::verb method);
    bool is_accepted_content_type(const std::string& content_type);

    Task<void> do_upgrade(const RequestWithStringBody& req);

    template <class Body>
    void set_cors(boost::beast::http::response<Body>& res);

    //! Perform an asynchronous read operation.
    Task<bool> do_read();

    //! Perform an asynchronous write operation.
    Task<void> do_write(const std::string& content, boost::beast::http::status http_status, const std::string& content_encoding = "");

    static std::string get_date_time();

    Task<void> compress(const std::string& clear_data, std::string& compressed_data);

    //! Socket for the connection.
    boost::asio::ip::tcp::socket socket_;

    RequestHandlerFactory& handler_factory_;

    //! The handler used to process the incoming request.
    RequestHandlerPtr handler_;

    const std::vector<std::string>& allowed_origins_;
    const std::optional<std::string> jwt_secret_;

    bool request_keep_alive_{false};
    unsigned int request_http_version_{11};

    boost::beast::flat_buffer data_;

    bool ws_upgrade_enabled_;

    bool ws_compression_;

    bool http_compression_;

    WorkerPool& workers_;

    std::string vary_;
    std::string origin_;
    boost::beast::http::verb method_{boost::beast::http::verb::unknown};
};

}  // namespace silkworm::rpc::http
