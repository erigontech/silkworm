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
//
// Copyright (c) 2003-2020 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "connection.hpp"

#include <exception>
#include <fstream>
#include <string_view>

#include <absl/strings/str_join.h>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/system/error_code.hpp>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/defaults.h>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc::http {

Connection::Connection(boost::asio::io_context& io_context,
                       commands::RpcApi& api,
                       commands::RpcApiTable& handler_table,
                       const std::vector<std::string>& allowed_origins,
                       std::optional<std::string> jwt_secret)
    : socket_{io_context},
      request_handler_{this, api, handler_table},
      allowed_origins_{allowed_origins},
      jwt_secret_{std ::move(jwt_secret)} {
    SILK_DEBUG << "Connection::Connection socket " << &socket_ << " created";
}

Connection::~Connection() {
    socket_.close();
    SILK_DEBUG << "Connection::~Connection socket " << &socket_ << " deleted";
}

Task<void> Connection::read_loop() {
    try {
        while (true) {
            co_await do_read();
        }
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::beast::http::error::end_of_stream || se.code() == boost::asio::error::broken_pipe) {
            SILK_DEBUG << "Connection::read_loop close from client with code: " << se.code();
        } else if (se.code() != boost::asio::error::operation_aborted) {
            SILK_ERROR << "Connection::read_loop system_error: " << se.what();
            throw;
        } else {
            SILK_DEBUG << "Connection::read_loop operation_aborted: " << se.what();
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::read_loop exception: " << e.what();
        throw;
    }
}

Task<void> Connection::do_read() {
    SILK_DEBUG << "Connection::do_read going to read...";

    boost::beast::http::request_parser<boost::beast::http::string_body> parser;
    unsigned long bytes_transferred;
    try {
        bytes_transferred = co_await boost::beast::http::async_read(socket_, data_, parser, boost::asio::use_awaitable);
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::beast::http::error::end_of_stream || se.code() == boost::asio::error::broken_pipe) {
            throw;
        } else {
            co_return;
        }
    }

    SILK_DEBUG << "Connection::do_read bytes_read: " << bytes_transferred;
    SILK_TRACE << "Connection::do_read: " << parser.get() << "\n";

    if (!parser.is_done()) {
        co_return;
    }
    request_keep_alive_ = parser.get().keep_alive();
    request_http_version_ = parser.get().version();

    if (boost::beast::websocket::is_upgrade(parser.get())) {
        co_return;
    }
    co_await handle_request(parser.get());
}

Task<void>
Connection::handle_request(boost::beast::http::request<boost::beast::http::string_body>& req) {
    if (!req.body().size()) {
        std::string content{};
        co_await do_write(content);
    } else {
        SILK_TRACE << "handle HTTP request content #size: " << req.body().size();
        SILK_TRACE << "handle HTTP request content: " << req.body();

        const auto auth_result = is_request_authorized(req);
        if (!auth_result) {
            auto content = make_json_error(0, 403, auth_result.error()).dump() + "\n";
            co_await do_write(content, boost::beast::http::status::forbidden);
        } else {
            co_await request_handler_.handle(req.body());
        }
    }
}

/* notification from request_handler */
Task<void>
Connection::write_rsp(std::string& content) {
    /* write rsp from request_handler */
    co_await do_write(content);
}

Task<void> Connection::open_stream() {
    /* write chunks header */
    try {
        boost::beast::http::response<boost::beast::http::empty_body> res{boost::beast::http::status::ok, request_http_version_};
        res.set(boost::beast::http::field::content_type, "application/json");
        res.chunked(true);

        // Set up the serializer
        boost::beast::http::response_serializer<boost::beast::http::empty_body> sr{res};

        co_await async_write_header(socket_, sr, boost::asio::use_awaitable);
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "Connection::open_stream system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::open_stream exception: " << e.what();
        throw;
    }
    co_return;
}

Task<std::size_t> Connection::write(std::string_view content) {
    /* write chunks */
    unsigned long bytes_transferred{0};
    try {
        bytes_transferred = co_await boost::asio::async_write(socket_, boost::asio::buffer(content), boost::asio::use_awaitable);
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "Connection::write system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::write exception: " << e.what();
        throw;
    }

    SILK_TRACE << "Connection::write bytes_transferred: " << bytes_transferred;
    co_return bytes_transferred;
}

Task<void> Connection::do_write(std::string& content, boost::beast::http::status http_status) {
    try {
        SILK_DEBUG << "Connection::do_write response: " << content;
        boost::beast::http::response<boost::beast::http::string_body> res{http_status, request_http_version_};
        res.set(boost::beast::http::field::content_type, "application/json");
        res.keep_alive(request_keep_alive_);
        res.content_length(content.size());
        res.body() = std::string(std::move(content));

        set_cors(res);

        res.prepare_payload();
        const auto bytes_transferred = co_await boost::beast::http::async_write(socket_, res, boost::asio::use_awaitable);

        SILK_TRACE << "Connection::do_write bytes_transferred: " << bytes_transferred;
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "Connection::do_write system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::do_write exception: " << e.what();
        throw;
    }
    co_return;
}

void Connection::set_cors(boost::beast::http::response<boost::beast::http::string_body>& res) {
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

Connection::AuthorizationResult Connection::is_request_authorized(boost::beast::http::request<boost::beast::http::string_body>& req) {
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

}  // namespace silkworm::rpc::http
