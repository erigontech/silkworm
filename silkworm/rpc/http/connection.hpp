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
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

#include <silkworm/rpc/commands/rpc_api_table.hpp>
#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/common/interface_log.hpp>
#include <silkworm/rpc/common/writer.hpp>
#include <silkworm/rpc/json_rpc/request_handler.hpp>
#include <silkworm/rpc/ws/connection.hpp>

namespace silkworm::rpc::http {

//! Represents a single connection from a client.
class Connection : public StreamWriter {
  public:
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    //! Construct a connection running within the given execution context.
    Connection(boost::asio::io_context& io_context,
               commands::RpcApi& api,
               commands::RpcApiTable& handler_table,
               const std::vector<std::string>& allowed_origins,
               std::optional<std::string> jwt_secret,
               bool ws_upgrade_enabled,
               bool ws_compression,
               bool http_compression,
               InterfaceLogSettings ifc_log_settings);
    ~Connection() override;

    boost::asio::ip::tcp::socket& socket() { return socket_; }

    //! Start the asynchronous read loop for the connection.
    Task<void> read_loop();

    /* StreamWriter Interface */
    Task<void> open_stream() override;
    Task<void> close_stream() override;
    Task<std::size_t> write(std::string_view content, bool last) override;

  private:
    using AuthorizationError = std::string;
    using AuthorizationResult = tl::expected<void, AuthorizationError>;
    AuthorizationResult is_request_authorized(const boost::beast::http::request<boost::beast::http::string_body>& req);

    Task<void> handle_request(const boost::beast::http::request<boost::beast::http::string_body>& req);
    Task<void> handle_actual_request(const boost::beast::http::request<boost::beast::http::string_body>& req);
    Task<void> handle_preflight(const boost::beast::http::request<boost::beast::http::string_body>& req);

    bool is_origin_allowed(const std::vector<std::string>& allowed_origins, const std::string& origin);
    bool is_method_allowed(boost::beast::http::verb method);
    bool is_accepted_content_type(const std::string& content_type);

    Task<void> do_upgrade(const boost::beast::http::request<boost::beast::http::string_body>& req);

    template <class Body>
    void set_cors(boost::beast::http::response<Body>& res);

    //! Perform an asynchronous read operation.
    Task<bool> do_read();

    //! Perform an asynchronous write operation.
    Task<void> do_write(const std::string& content, boost::beast::http::status http_status, bool compress = false);

    static std::string get_date_time();

    void compress_data(const std::string& clear_data, std::string& compressed_data);

    //! Socket for the connection.
    boost::asio::ip::tcp::socket socket_;

    commands::RpcApi& api_;
    const commands::RpcApiTable& handler_table_;

    //! The handler used to process the incoming request.
    json_rpc::RequestHandler request_handler_;

    const std::vector<std::string>& allowed_origins_;
    const std::optional<std::string> jwt_secret_;

    bool request_keep_alive_{false};
    unsigned int request_http_version_{11};

    boost::beast::flat_buffer data_;

    bool ws_upgrade_enabled_;

    bool ws_compression_;

    bool http_compression_;

    std::string vary_;
    std::string origin_;
    boost::beast::http::verb method_{boost::beast::http::verb::unknown};

    char temp_compressed_buffer_[10 * kMebi]{};
};

}  // namespace silkworm::rpc::http
