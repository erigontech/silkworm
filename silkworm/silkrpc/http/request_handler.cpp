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

#include "request_handler.hpp"

#include <iostream>
#include <vector>

#include <boost/asio/write.hpp>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/defaults.h>
#include <nlohmann/json.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/silkrpc/commands/eth_api.hpp>
#include <silkworm/silkrpc/common/clock_time.hpp>
#include <silkworm/silkrpc/http/header.hpp>
#include <silkworm/silkrpc/types/writer.hpp>

namespace silkworm::rpc::http {

boost::asio::awaitable<void> RequestHandler::handle(const http::Request& request) {
    auto start = clock_time::now();

    http::Reply reply;
    if (request.content.empty()) {
        reply.content = "";
        reply.status = http::StatusType::no_content;
    } else {
        SILK_DEBUG << "handle_user_request content: " << request.content;

        const auto request_json = nlohmann::json::parse(request.content);

        if (request_json.is_object()) {
            if (!request_json.contains("id")) {
                reply.content = "\n";
                reply.status = http::StatusType::ok;
            } else {
                const auto request_id = request_json["id"].get<uint32_t>();
                const auto error = co_await is_request_authorized(request);
                if (error.has_value()) {
                    reply.content = make_json_error(request_id, 403, error.value()).dump() + "\n";
                    reply.status = http::StatusType::unauthorized;
                } else {
                    co_await handle_request_and_create_reply(request_json, reply);
                    reply.content += "\n";
                }
            }
        } else {
            std::string batch_reply_content = "[";
            bool first_element = true;
            for (auto& item : request_json.items()) {
                const auto& item_json = item.value();
                if (!item_json.contains("id")) {
                    reply.content = "\n";
                    reply.status = http::StatusType::ok;
                } else {
                    auto request_id = item_json["id"].get<uint32_t>();
                    const auto error = co_await is_request_authorized(request);
                    if (error.has_value()) {
                        reply.content = make_json_error(request_id, 403, error.value()).dump() + "\n";
                        reply.status = http::StatusType::unauthorized;
                    } else {
                        if (first_element) {
                            first_element = false;
                        } else {
                            batch_reply_content += ",";
                        }
                        co_await handle_request_and_create_reply(item_json, reply);
                        batch_reply_content += reply.content;
                    }
                }
            }
            batch_reply_content += "]\n";
            reply.content = batch_reply_content;
        }
    }

    co_await do_write(reply);

    SILK_INFO << "handle_user_request t=" << clock_time::since(start) << "ns";
}

boost::asio::awaitable<void> RequestHandler::handle_request_and_create_reply(const nlohmann::json& request_json, http::Reply& reply) {
    const auto request_id = request_json["id"].get<uint32_t>();
    if (!request_json.contains("method")) {
        reply.content = make_json_error(request_id, -32600, "invalid request").dump();
        reply.status = http::StatusType::bad_request;
        co_return;
    }

    const auto method = request_json["method"].get<std::string>();
    if (method.empty()) {
        reply.content = make_json_error(request_id, -32600, "invalid request").dump();
        reply.status = http::StatusType::bad_request;
        co_return;
    }

    // Dispatch JSON handlers in this order: 1) glaze JSON 2) nlohmann JSON 3) JSON streaming
    const auto json_glaze_handler = rpc_api_table_.find_json_glaze_handler(method);
    if (json_glaze_handler) {
        co_await handle_request(request_id, *json_glaze_handler, request_json, reply);
        co_return;
    }
    const auto json_handler = rpc_api_table_.find_json_handler(method);
    if (json_handler) {
        co_await handle_request(request_id, *json_handler, request_json, reply);
        co_return;
    }
    const auto stream_handler = rpc_api_table_.find_stream_handler(method);
    if (stream_handler) {
        co_await handle_request(*stream_handler, request_json);
        co_return;
    }

    reply.content = make_json_error(request_id, -32601, "the method " + method + " does not exist/is not available").dump();
    reply.status = http::StatusType::not_implemented;

    co_return;
}

boost::asio::awaitable<void> RequestHandler::handle_request(uint32_t request_id, commands::RpcApiTable::HandleMethodGlaze handler, const nlohmann::json& request_json, http::Reply& reply) {
    try {
        std::string reply_json;
        reply_json.reserve(2048);
        co_await (rpc_api_.*handler)(request_json, reply_json);
        reply.status = http::StatusType::ok;
        reply.content = std::move(reply_json);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what();
        reply.content = make_json_error(request_id, 100, e.what()).dump();
        reply.status = http::StatusType::internal_server_error;
    } catch (...) {
        SILK_ERROR << "unexpected exception";
        reply.content = make_json_error(request_id, 100, "unexpected exception").dump();
        reply.status = http::StatusType::internal_server_error;
    }

    co_return;
}

boost::asio::awaitable<void> RequestHandler::handle_request(uint32_t request_id, commands::RpcApiTable::HandleMethod handler, const nlohmann::json& request_json, http::Reply& reply) {
    try {
        nlohmann::json reply_json;
        co_await (rpc_api_.*handler)(request_json, reply_json);
        reply.content = reply_json.dump(
            /*indent=*/-1, /*indent_char=*/' ', /*ensure_ascii=*/false, nlohmann::json::error_handler_t::replace);
        reply.status = http::StatusType::ok;

    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what();
        reply.content = make_json_error(request_id, 100, e.what()).dump();
        reply.status = http::StatusType::internal_server_error;
    } catch (...) {
        SILK_ERROR << "unexpected exception";
        reply.content = make_json_error(request_id, 100, "unexpected exception").dump();
        reply.status = http::StatusType::internal_server_error;
    }

    co_return;
}

boost::asio::awaitable<void> RequestHandler::handle_request(commands::RpcApiTable::HandleStream handler, const nlohmann::json& request_json) {
    try {
        SocketWriter socket_writer(socket_);
        ChunksWriter chunks_writer(socket_writer);
        json::Stream stream(chunks_writer);

        co_await write_headers();
        co_await (rpc_api_.*handler)(request_json, stream);

        stream.close();
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what();
    } catch (...) {
        SILK_ERROR << "unexpected exception";
    }

    co_return;
}

boost::asio::awaitable<std::optional<std::string>> RequestHandler::is_request_authorized(const http::Request& request) {
    if (!jwt_secret_.has_value() || (*jwt_secret_).empty()) {
        co_return std::nullopt;
    }

    const auto it = std::find_if(request.headers.begin(), request.headers.end(), [&](const Header& h) {
        return h.name == "Authorization";
    });

    if (it == request.headers.end()) {
        SILK_ERROR << "JWT request without Authorization in auth connection";
        co_return "missing Authorization Header";
    }

    std::string client_token;
    if (it->value.substr(0, 7) == "Bearer ") {
        client_token = it->value.substr(7);
    } else {
        SILK_ERROR << "JWT client request without token";
        co_return "missing token";
    }
    try {
        // Parse token
        auto decoded_client_token = jwt::decode(client_token);
        if (decoded_client_token.has_issued_at() == 0) {
            SILK_ERROR << "JWT iat (Issued At) not defined";
            co_return "iat(Issued At) not defined";
        }
        // Validate token
        auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::hs256{*jwt_secret_});

        SILK_TRACE << "jwt client token: " << client_token << " jwt_secret: " << *jwt_secret_;
        verifier.verify(decoded_client_token);
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "JWT invalid token: " << se.what();
        co_return "invalid token";
    } catch (const std::exception& se) {
        SILK_ERROR << "JWT invalid token: " << se.what();
        co_return "invalid token";
    }

    co_return std::nullopt;
}

boost::asio::awaitable<void> RequestHandler::do_write(Reply& reply) {
    try {
        SILK_DEBUG << "RequestHandler::do_write reply: " << reply.content;

        reply.headers.reserve(2);
        reply.headers.emplace_back(http::Header{"Content-Length", std::to_string(reply.content.size())});
        reply.headers.emplace_back(http::Header{"Content-Type", "application/json"});

        const auto bytes_transferred = co_await boost::asio::async_write(socket_, reply.to_buffers(), boost::asio::use_awaitable);
        SILK_TRACE << "RequestHandler::do_write bytes_transferred: " << bytes_transferred;
    } catch (const boost::system::system_error& se) {
        std::rethrow_exception(std::make_exception_ptr(se));
    } catch (const std::exception& e) {
        std::rethrow_exception(std::make_exception_ptr(e));
    }
}

boost::asio::awaitable<void> RequestHandler::write_headers() {
    try {
        std::vector<http::Header> headers;
        headers.reserve(2);
        headers.emplace_back(http::Header{"Content-Type", "application/json"});
        headers.emplace_back(http::Header{"Transfer-Encoding", "chunked"});

        auto buffers = http::to_buffers(StatusType::ok, headers);

        const auto bytes_transferred = co_await boost::asio::async_write(socket_, buffers, boost::asio::use_awaitable);

        SILK_TRACE << "RequestHandler::write_headers bytes_transferred: " << bytes_transferred;
    } catch (const std::system_error& se) {
        std::rethrow_exception(std::make_exception_ptr(se));
    } catch (const std::exception& e) {
        std::rethrow_exception(std::make_exception_ptr(e));
    }
}

}  // namespace silkworm::rpc::http
