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
        if (se.code() == boost::beast::http::error::end_of_stream) {
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
    int bytes_transferred;
    try {
        bytes_transferred = co_await boost::beast::http::async_read(socket_, data_, parser, boost::asio::use_awaitable);
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::beast::http::error::end_of_stream) {
            std::rethrow_exception(std::make_exception_ptr(se));
        } else {
            Response msg_response{};
            msg_response.status = Channel::ResponseStatus::bad_request;
            msg_response.content = make_json_error(0, -32600, "invalid request").dump() + "\n";
            co_await do_write(msg_response);
            co_return;
        }
    }

    SILK_DEBUG << "Connection::do_read bytes_read: " << bytes_transferred;
    SILK_TRACE << "Connection::do_read: " << parser.get() << "\n";

    if (!parser.is_done()) {
        co_return;
    }

    if (boost::beast::websocket::is_upgrade(parser.get())) {
        co_return;
    }

#ifdef notdef
    if (jwt) {
        Response response;
        msg_response.status = Channel::ResponseStatus::processing_continue;
        co_await do_write(msg_response);
        else {
#endif
            co_await handle_request(parser);
        }

        Task<void>
        Connection::handle_request(boost::beast::http::request_parser<boost::beast::http::string_body> & parser) {
            Response response;
            auto& message = parser.get();

            request_keep_alive_ = message.keep_alive();
            request_http_version_ = message.version();
            if (!message.body().size()) {
                response.content = "";
                response.status = Channel::ResponseStatus::no_content;
                co_await do_write(response);
            } else {
                SILK_TRACE << "handle HTTP request content #size: " << *parser.content_length();

                const auto auth_result = is_request_authorized(parser);
                if (!auth_result) {
                    response.content = make_json_error(0, 403, auth_result.error()).dump() + "\n";
                    response.status = Channel::ResponseStatus::unauthorized;
                    co_await do_write(response);
                } else {
                    co_await request_handler_.handle(message.body());
                }
            }
        }

        boost::beast::http::status Connection::get_http_status(Channel::ResponseStatus status) {
            switch (status) {
                case ResponseStatus::processing_continue:
                    return boost::beast::http::status::processing;
                case ResponseStatus::ok:
                    return boost::beast::http::status::ok;
                case ResponseStatus::created:
                    return boost::beast::http::status::created;
                case ResponseStatus::accepted:
                    return boost::beast::http::status::accepted;
                case ResponseStatus::no_content:
                    return boost::beast::http::status::no_content;
                case ResponseStatus::multiple_choices:
                    return boost::beast::http::status::multiple_choices;
                case ResponseStatus::moved_permanently:
                    return boost::beast::http::status::moved_permanently;
                case ResponseStatus::not_modified:
                    return boost::beast::http::status::not_modified;
                case ResponseStatus::bad_request:
                    return boost::beast::http::status::bad_request;
                case ResponseStatus::unauthorized:
                    return boost::beast::http::status::unauthorized;
                case ResponseStatus::forbidden:
                    return boost::beast::http::status::forbidden;
                case ResponseStatus::not_found:
                    return boost::beast::http::status::not_found;
                case ResponseStatus::internal_server_error:
                    return boost::beast::http::status::internal_server_error;
                case ResponseStatus::not_implemented:
                    return boost::beast::http::status::not_implemented;
                case ResponseStatus::bad_gateway:
                    return boost::beast::http::status::bad_gateway;
                case ResponseStatus::service_unavailable:
                    return boost::beast::http::status::service_unavailable;
                default:
                    return boost::beast::http::status::internal_server_error;
            }
        }

        /* notification from request_handler */
        Task<void>
        Connection::write_rsp(Response & msg_response) {
            co_await do_write(msg_response);
        }

        Task<void> Connection::open_stream() {
            /* write chunk headers */
            co_await write_headers();
        }

        Task<std::size_t> Connection::write(std::string_view content) {
            /* write chunks */
            const auto bytes_transferred = co_await boost::asio::async_write(socket_, boost::asio::buffer(content), boost::asio::use_awaitable);
            SILK_TRACE << "Connection::write bytes_transferred: " << bytes_transferred;
            co_return bytes_transferred;
        }

        //! The number of HTTP headers added when Cross-Origin Resource Sharing (CORS) is enabled.
        static constexpr size_t kCorsNumHeaders{4};

        Task<void> Connection::do_write(Response & response) {
            try {
                SILK_DEBUG << "Connection::do_write response: " << response.content;
                auto http_status = get_http_status(response.status);
                boost::beast::http::response<boost::beast::http::string_body> res{http_status, request_http_version_};
                res.set(boost::beast::http::field::server, "erigon/rpcdaemon");
                res.set(boost::beast::http::field::content_type, "application/json");
                res.keep_alive(request_keep_alive_);
                res.content_length(response.content.size());
                res.body() = std::string(std::move(response.content));

                // set_cors(reply.headers); //TODO

                res.prepare_payload();
                const auto bytes_transferred = co_await boost::beast::http::async_write(socket_, res, boost::asio::use_awaitable);

                SILK_TRACE << "Connection::do_write bytes_transferred: " << bytes_transferred;
            } catch (const boost::system::system_error& se) {
                std::rethrow_exception(std::make_exception_ptr(se));
            } catch (const std::exception& e) {
                std::rethrow_exception(std::make_exception_ptr(e));
            }
            co_return;
        }

        Task<void> Connection::write_headers() {
#ifdef notdef
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
#endif
            co_return;
        }

#ifdef notdef
        void Connection::set_cors(std::vector<Header> & headers) {
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
#endif

        Connection::AuthorizationResult Connection::is_request_authorized(boost::beast::http::request_parser<boost::beast::http::string_body> & parser) {
            boost::ignore_unused(parser);

            if (!jwt_secret_.has_value() || (*jwt_secret_).empty()) {
                return {};
            }

#ifdef notdef
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
#endif
            return {};
        }

    }  // namespace silkworm::rpc::http
