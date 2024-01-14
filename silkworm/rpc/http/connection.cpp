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
    request_.content.reserve(kRequestContentInitialCapacity);
    request_.headers.reserve(kRequestHeadersInitialCapacity);
    request_.method.reserve(kRequestMethodInitialCapacity);
    request_.uri.reserve(kRequestUriInitialCapacity);
    SILK_DEBUG << "Connection::Connection socket " << &socket_ << " created";
}

Connection::~Connection() {
    socket_.close();
    SILK_DEBUG << "Connection::~Connection socket " << &socket_ << " deleted";
}

Task<void> Connection::read_loop() {
    try {
        // Read next request or next chunk (result == RequestParser::indeterminate) until closed or error
        while (true) {
            co_await do_read();
        }
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::asio::error::eof || se.code() == boost::asio::error::connection_reset || se.code() == boost::asio::error::broken_pipe) {
            SILK_DEBUG << "Connection::read_loop close from client with code: " << se.code();
        } else if (se.code() != boost::asio::error::operation_aborted) {
            SILK_ERROR << "Connection::read_loop system_error: " << se.what();
            std::rethrow_exception(std::make_exception_ptr(se));
        } else {
            SILK_DEBUG << "Connection::read_loop operation_aborted: " << se.what();
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::read_loop exception: " << e.what();
        std::rethrow_exception(std::make_exception_ptr(e));
    }
}

Task<void> Connection::do_read() {
    SILK_DEBUG << "Connection::do_read going to read...";

    boost::beast::http::request_parser<boost::beast::http::string_body> parser;
    // Apply a reasonable limit to the allowed size
    // of the body in bytes to prevent abuse.
    parser.body_limit(10000);
    // Construct a new parser for each message
    parser.header_limit(10000);

    auto bytes_transferred = co_await boost::beast::http::async_read_some(socket_, data_, parser, boost::asio::use_awaitable);
    SILK_DEBUG << "Connection::do_read bytes_read: " << bytes_transferred;

    if (bytes_transferred && parser.is_done()) {
        int length = 0;
        if (parser.content_length()) {
            length = *parser.content_length();
        }
        std::cout << "http:content_length: " << length << "\n";
    }
    if (boost::beast::websocket::is_upgrade(parser.get())) {
        std::cout << "http upgrade\n";
    }
    parser.release();

    // rqeuest object should not be used

#ifdef notdef
    if (result == RequestParser::ResultType::good) {
        co_await handle_request(request_);
        clean();
    } else if (result == RequestParser::ResultType::bad) {
        reply_ = Reply::stock_reply(StatusType::bad_request);
        co_await do_write();
        clean();
    } else if (result == RequestParser::ResultType::processing_continue) {
        reply_ = Reply::stock_reply(StatusType::processing_continue);
        co_await do_write();
        reply_.reset();
    }
#endif
}

Task<void>
Connection::handle_request(Request& request) {
    http::Reply reply;

    if (request.content.empty()) {
        reply.content = "";
        reply.status = http::StatusType::no_content;
        co_await do_write(reply);
    } else {
        SILK_TRACE << "handle HTTP request content #size: " << request.content.size();

        const auto auth_result = is_request_authorized(request);
        if (!auth_result) {
            reply.content = make_json_error(0, 403, auth_result.error()).dump() + "\n";
            reply.status = http::StatusType::unauthorized;
        }
        co_await request_handler_.handle(request.content);
    }
}

StatusType Connection::get_http_status(Channel::ResponseStatus status) {
    switch (status) {
        case ResponseStatus::processing_continue:
            return StatusType::processing_continue;
        case ResponseStatus::ok:
            return StatusType::ok;
        case ResponseStatus::created:
            return StatusType::created;
        case ResponseStatus::accepted:
            return StatusType::accepted;
        case ResponseStatus::no_content:
            return StatusType::no_content;
        case ResponseStatus::multiple_choices:
            return StatusType::multiple_choices;
        case ResponseStatus::moved_permanently:
            return StatusType::moved_permanently;
        case ResponseStatus::moved_temporarily:
            return StatusType::moved_temporarily;
        case ResponseStatus::not_modified:
            return StatusType::not_modified;
        case ResponseStatus::bad_request:
            return StatusType::bad_request;
        case ResponseStatus::unauthorized:
            return StatusType::unauthorized;
        case ResponseStatus::forbidden:
            return StatusType::forbidden;
        case ResponseStatus::not_found:
            return StatusType::not_found;
        case ResponseStatus::internal_server_error:
            return StatusType::internal_server_error;
        case ResponseStatus::not_implemented:
            return StatusType::not_implemented;
        case ResponseStatus::bad_gateway:
            return StatusType::bad_gateway;
        case ResponseStatus::service_unavailable:
            return StatusType::service_unavailable;
        default:
            return StatusType::internal_server_error;
    }
}

/* notification from request_handler */
Task<void>
Connection::write_rsp(Response& msg_response) {
    Reply reply;
    reply.status = get_http_status(msg_response.status);
    reply.content = std::move(msg_response.content);
    co_await do_write(reply);
}

Task<void> Connection::open_stream() {
    co_await write_headers();
}

Task<std::size_t> Connection::write(std::string_view content) {
    const auto bytes_transferred = co_await boost::asio::async_write(socket_, boost::asio::buffer(content), boost::asio::use_awaitable);
    SILK_TRACE << "Connection::write bytes_transferred: " << bytes_transferred;
    co_return bytes_transferred;
}

void Connection::clean() {
    request_.reset();
    request_parser_.reset();
    reply_.reset();
}

Task<void> Connection::do_write() {
    SILK_DEBUG << "Connection::do_write reply: " << reply_.content;
    const auto bytes_transferred = co_await boost::asio::async_write(socket_, reply_.to_buffers(), boost::asio::use_awaitable);

    // const auto bytes_transferred  =  co_await boost::beast::async_write(socket_, std::move(response_queue_.front()), boost::asio::use_awaitable);

    SILK_TRACE << "Connection::do_write bytes_transferred: " << bytes_transferred;
}

//! The number of HTTP headers added when Cross-Origin Resource Sharing (CORS) is enabled.
static constexpr size_t kCorsNumHeaders{4};

Task<void> Connection::do_write(Reply& reply) {
    try {
        SILK_DEBUG << "Connection::do_write reply: " << reply.content;

        reply.headers.reserve(allowed_origins_.empty() ? 2 : 2 + kCorsNumHeaders);
        reply.headers.emplace_back(http::Header{"Content-Length", std::to_string(reply.content.size())});
        reply.headers.emplace_back(http::Header{"Content-Type", "application/json"});

        set_cors(reply.headers);

        const auto bytes_transferred = co_await boost::asio::async_write(socket_, reply.to_buffers(), boost::asio::use_awaitable);
        SILK_TRACE << "Connection::do_write bytes_transferred: " << bytes_transferred;
    } catch (const boost::system::system_error& se) {
        std::rethrow_exception(std::make_exception_ptr(se));
    } catch (const std::exception& e) {
        std::rethrow_exception(std::make_exception_ptr(e));
    }
}

Task<void> Connection::write_headers() {
    try {
        std::vector<http::Header> headers;
        headers.reserve(allowed_origins_.empty() ? 2 : 2 + kCorsNumHeaders);
        headers.emplace_back(http::Header{"Content-Type", "application/json"});
        headers.emplace_back(http::Header{"Transfer-Encoding", "chunked"});

        set_cors(headers);

        auto buffers = http::to_buffers(StatusType::ok, headers);

        const auto bytes_transferred = co_await boost::asio::async_write(socket_, buffers, boost::asio::use_awaitable);
        SILK_TRACE << "Connection::write_headers bytes_transferred: " << bytes_transferred;
    } catch (const std::system_error& se) {
        std::rethrow_exception(std::make_exception_ptr(se));
    } catch (const std::exception& e) {
        std::rethrow_exception(std::make_exception_ptr(e));
    }
}

void Connection::set_cors(std::vector<Header>& headers) {
    if (allowed_origins_.empty()) {
        return;
    }

    if (allowed_origins_.at(0) == "*") {
        headers.emplace_back(http::Header{"Access-Control-Allow-Origin", "*"});
    } else {
        headers.emplace_back(http::Header{"Access-Control-Allow-Origin", absl::StrJoin(allowed_origins_, ",")});
    }
    headers.emplace_back(http::Header{"Access-Control-Allow-Methods", "GET, POST"});
    headers.emplace_back(http::Header{"Access-Control-Allow-Headers", "*"});
    headers.emplace_back(http::Header{"Access-Control-Max-Age", "600"});
}

Connection::AuthorizationResult Connection::is_request_authorized(const http::Request& request) {
    if (!jwt_secret_.has_value() || (*jwt_secret_).empty()) {
        return {};
    }

    const auto it = std::find_if(request.headers.begin(), request.headers.end(), [&](const Header& h) {
        return h.name == "Authorization";
    });

    if (it == request.headers.end()) {
        SILK_ERROR << "JWT request without Authorization Header: " << request;
        return tl::make_unexpected("missing Authorization Header");
    }

    std::string client_token;
    if (it->value.substr(0, 7) == "Bearer ") {
        client_token = it->value.substr(7);
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
