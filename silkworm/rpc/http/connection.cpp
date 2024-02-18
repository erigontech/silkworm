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

#include "connection.hpp"

#include <exception>
#include <string_view>

#include <absl/strings/str_join.h>
#include <boost/asio/buffer.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/http/chunk_encode.hpp>
#include <boost/beast/http/write.hpp>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/defaults.h>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc::http {

Connection::Connection(boost::asio::io_context& io_context,
                       commands::RpcApi& api,
                       commands::RpcApiTable& handler_table,
                       const std::vector<std::string>& allowed_origins,
                       std::optional<std::string> jwt_secret,
                       bool use_websocket,
                       bool ws_compression,
                       InterfaceLogSettings ifc_log_settings)
    : socket_{io_context},
      api_{api},
      handler_table_{handler_table},
      request_handler_{this, api, handler_table, std::move(ifc_log_settings)},
      allowed_origins_{allowed_origins},
      jwt_secret_{std ::move(jwt_secret)},
      use_websocket_{use_websocket},
      ws_compression_{ws_compression} {
    SILK_TRACE << "Connection::Connection socket " << &socket_ << " created";
}

Connection::~Connection() {
    socket_.close();
    SILK_TRACE << "Connection::~Connection socket " << &socket_ << " deleted";
}

Task<void> Connection::read_loop() {
    try {
        bool continue_processing{true};
        while (continue_processing) {
            continue_processing = co_await do_read();
        }
    } catch (const boost::system::system_error& se) {
        SILK_TRACE << "Connection::read_loop system-error: " << se.code();
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::read_loop exception: " << e.what();
    }
}

Task<bool> Connection::do_read() {
    SILK_TRACE << "Connection::do_read going to read...";

    boost::beast::http::request_parser<boost::beast::http::string_body> parser;
    auto bytes_transferred = co_await boost::beast::http::async_read(socket_, data_, parser, boost::asio::use_awaitable);

    SILK_TRACE << "Connection::do_read bytes_read: " << bytes_transferred << " [" << parser.get() << "]";

    if (!parser.is_done()) {
        co_return true;
    }
    request_keep_alive_ = parser.get().keep_alive();
    request_http_version_ = parser.get().version();

    if (boost::beast::websocket::is_upgrade(parser.get())) {
        if (use_websocket_) {
            co_await do_upgrade(parser.release());
            co_return false;
        } else {
            // If it does not (or cannot) upgrade the connection, it ignores the Upgrade header and sends back a regular response (OK)
            co_await do_write("", boost::beast::http::status::ok);
        }
        co_return true;
    }
    co_await handle_request(parser.release());
    co_return true;
}

Task<void> Connection::do_upgrade(const boost::beast::http::request<boost::beast::http::string_body>& req) {
    // Now that talking to the socket is successful,
    // we tie the socket object to a websocket stream
    boost::beast::websocket::stream<boost::beast::tcp_stream> stream(std::move(socket_));

    auto ws_connection = std::make_shared<ws::Connection>(std::move(stream), api_, std::move(handler_table_), ws_compression_);
    co_await ws_connection->accept(req);

    auto connection_loop = [](auto websocket_connection) -> Task<void> { co_await websocket_connection->read_loop(); };

    boost::asio::co_spawn(socket_.get_executor(), connection_loop(ws_connection), boost::asio::detached);
}

Task<void> Connection::handle_request(const boost::beast::http::request<boost::beast::http::string_body>& req) {
    if (req.body().empty()) {
        std::string rsp_content;
        co_await do_write(rsp_content);
    } else {
        SILK_TRACE << "Connection::handle_request body size: " << req.body().size() << " data: " << req.body();

        const auto auth_result = is_request_authorized(req);
        if (!auth_result) {
            auto rsp_content = make_json_error(0, 403, auth_result.error()).dump() + "\n";
            co_await do_write(rsp_content, boost::beast::http::status::forbidden);
        } else {
            auto rsp_content = co_await request_handler_.handle(req.body());
            if (rsp_content) {
                co_await do_write(*rsp_content);
            }
        }
    }
}

//! Write chunked response headers
Task<void> Connection::open_stream() {
    try {
        boost::beast::http::response<boost::beast::http::empty_body> rsp{boost::beast::http::status::ok, request_http_version_};
        rsp.set(boost::beast::http::field::content_type, "application/json");
        rsp.set(boost::beast::http::field::date, get_date_time());
        rsp.chunked(true);

        set_cors<boost::beast::http::empty_body>(rsp);

        boost::beast::http::response_serializer<boost::beast::http::empty_body> serializer{rsp};

        co_await async_write_header(socket_, serializer, boost::asio::use_awaitable);
    } catch (const boost::system::system_error& se) {
        SILK_TRACE << "Connection::open_stream system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::open_stream exception: " << e.what();
        throw;
    }
    co_return;
}
Task<void> Connection::close_stream() {
    try {
        co_await boost::asio::async_write(socket_, boost::beast::http::make_chunk_last(), boost::asio::use_awaitable);
    } catch (const boost::system::system_error& se) {
        SILK_TRACE << "Connection::close system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::close exception: " << e.what();
        throw;
    }
    co_return;
}

//! Write chunked response content to the underlying socket
Task<std::size_t> Connection::write(std::string_view content, bool /*last*/) {
    unsigned long bytes_transferred{0};
    try {
        boost::asio::const_buffer buffer{content.data(), content.size()};
        bytes_transferred = co_await boost::asio::async_write(socket_, boost::beast::http::chunk_body(buffer), boost::asio::use_awaitable);
    } catch (const boost::system::system_error& se) {
        SILK_TRACE << "Connection::write system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::write exception: " << e.what();
        throw;
    }

    SILK_TRACE << "Connection::write bytes_transferred: " << bytes_transferred;
    co_return bytes_transferred;
}

Task<void> Connection::do_write(const std::string& content, boost::beast::http::status http_status) {
    try {
        SILK_TRACE << "Connection::do_write response: " << content;
        boost::beast::http::response<boost::beast::http::string_body> res{http_status, request_http_version_};
        res.set(boost::beast::http::field::content_type, "application/json");
        res.set(boost::beast::http::field::date, get_date_time());
        res.erase(boost::beast::http::field::host);
        res.keep_alive(request_keep_alive_);
        res.content_length(content.size());
        res.body() = content;

        set_cors<boost::beast::http::string_body>(res);

        res.prepare_payload();
        const auto bytes_transferred = co_await boost::beast::http::async_write(socket_, res, boost::asio::use_awaitable);

        SILK_TRACE << "Connection::do_write bytes_transferred: " << bytes_transferred;
    } catch (const boost::system::system_error& se) {
        SILK_TRACE << "Connection::do_write system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::do_write exception: " << e.what();
        throw;
    }
    co_return;
}

Connection::AuthorizationResult Connection::is_request_authorized(const boost::beast::http::request<boost::beast::http::string_body>& req) {
    if (!jwt_secret_.has_value() || (*jwt_secret_).empty()) {
        return {};
    }

    auto it = req.find("Authorization");
    if (it == req.end()) {
        SILK_ERROR << "JWT request without Authorization Header: " << req.body();
        return tl::make_unexpected("missing Authorization header");
    }

    std::string client_token;
    if (it->value().substr(0, 7) == "Bearer ") {
        client_token = it->value().substr(7);
    } else {
        SILK_ERROR << "JWT client request without token";
        return tl::make_unexpected("missing token");
    }
    try {
        // Parse token
        auto decoded_client_token = jwt::decode(client_token);
        if (decoded_client_token.has_issued_at() == 0) {
            SILK_ERROR << "JWT iat (Issued At) not defined";
            return tl::make_unexpected("iat(Issued At) not defined");
        }
        // Validate token
        auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::hs256{*jwt_secret_});

        SILK_TRACE << "JWT client token: " << client_token << " secret: " << *jwt_secret_;
        verifier.verify(decoded_client_token);
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "JWT invalid token: " << se.what();
        return tl::make_unexpected("invalid token");
    } catch (const std::exception& se) {
        SILK_ERROR << "JWT invalid token: " << se.what();
        return tl::make_unexpected("invalid token");
    }
    return {};
}

template <class Body>
void Connection::set_cors(boost::beast::http::response<Body>& res) {
    if (allowed_origins_.empty()) {
        return;
    }

    if (allowed_origins_.at(0) == "*") {
        res.set("Access-Control-Allow-Origin", "*");
    } else {
        res.set("Access-Control-Allow-Origin", absl::StrJoin(allowed_origins_, ","));
    }
    res.set("Access-Control-Allow-Methods", "GET, POST");
    res.set("Access-Control-Allow-Headers", "*");
    res.set("Access-Control-Max-Age", "600");
}

std::string Connection::get_date_time() {
    static const absl::TimeZone tz{absl::LocalTimeZone()};
    const absl::Time now{absl::Now()};

    std::stringstream ss;
    ss << absl::FormatTime("%a, %d %b %E4Y %H:%M:%S ", now, tz) << tz.name();
    return ss.str();
}

}  // namespace silkworm::rpc::http
