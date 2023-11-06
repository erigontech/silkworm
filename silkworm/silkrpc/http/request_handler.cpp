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
#include <sstream>
#include <vector>

#include <absl/strings/str_join.h>
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

Task<void> RequestHandler::handle(const http::Request& request) {
    auto start = clock_time::now();

    http::Reply reply;
    if (request.content.empty()) {
        reply.content = "";
        reply.status = http::StatusType::no_content;
    } else {
        SILK_TRACE << "handle HTTP request content #size: " << request.content.size();

        const auto auth_result = is_request_authorized(request);
        if (!auth_result) {
            reply.content = make_json_error(0, 403, auth_result.error()).dump() + "\n";
            reply.status = http::StatusType::unauthorized;
        } else {
            const auto request_json = nlohmann::json::parse(request.content);
            if (request_json.is_object()) {
                if (!is_valid_jsonrpc(request_json)) {
                    reply.status = http::StatusType::bad_request;
                    reply.content = make_json_error(0, -32600, "invalid request").dump() + "\n";
                } else {
                    co_await handle_request_and_create_reply(request_json, reply);
                    reply.content += "\n";
                }
            } else {
                std::stringstream batch_reply_content;
                batch_reply_content << "[";
                int index = 0;
                for (auto& item : request_json.items()) {
                    if (index++ > 0) {
                        batch_reply_content << ",";
                    }

                    if (!is_valid_jsonrpc(item.value())) {
                        batch_reply_content << make_json_error(0, -32600, "invalid request").dump();
                    } else {
                        http::Reply single_reply;
                        co_await handle_request_and_create_reply(item.value(), single_reply);
                        batch_reply_content << single_reply.content;
                    }
                }
                batch_reply_content << "]\n";

                reply.status = http::StatusType::ok;
                reply.content = batch_reply_content.str();
            }
        }
    }

    co_await do_write(reply);

    SILK_TRACE << "handle HTTP request t=" << clock_time::since(start) << "ns";
}

bool RequestHandler::is_valid_jsonrpc(const nlohmann::json& request_json) {
    const std::string valid_jsonrpc_version = "2.0";

    // for each property in request_json
    for (auto& property : request_json.items()) {
        const auto& property_name = property.key();

        SILK_TRACE << property_name << " : " << property.value().type_name() << " : " << property.value().dump();

        if (property_name == "id") {
            if (!property.value().is_number()) {
                return false;
            }
        } else if (property_name == "jsonrpc") {
            if (property.value() != valid_jsonrpc_version) {
                return false;
            }
        } else if (property_name == "method") {
            if (!property.value().is_string()) {
                return false;
            }
        } else if (property_name == "params") {
            if (!property.value().is_array()) {
                return false;
            }
        } else {
            return false;
        }
    }

    return true;
}

Task<void> RequestHandler::handle_request_and_create_reply(const nlohmann::json& request_json, http::Reply& reply) {
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
        SILK_TRACE << "--> handle RPC request: " << method;
        co_await handle_request(request_id, *json_glaze_handler, request_json, reply);
        SILK_TRACE << "<-- handle RPC request: " << method;
        co_return;
    }
    const auto json_handler = rpc_api_table_.find_json_handler(method);
    if (json_handler) {
        SILK_TRACE << "--> handle RPC request: " << method;
        co_await handle_request(request_id, *json_handler, request_json, reply);
        SILK_TRACE << "<-- handle RPC request: " << method;
        co_return;
    }
    const auto stream_handler = rpc_api_table_.find_stream_handler(method);
    if (stream_handler) {
        SILK_TRACE << "--> handle RPC stream request: " << method;
        co_await handle_request(*stream_handler, request_json);
        SILK_TRACE << "<-- handle RPC stream request: " << method;
        co_return;
    }

    reply.content = make_json_error(request_id, -32601, "the method " + method + " does not exist/is not available").dump();
    reply.status = http::StatusType::not_implemented;

    co_return;
}

Task<void> RequestHandler::handle_request(uint32_t request_id, commands::RpcApiTable::HandleMethodGlaze handler, const nlohmann::json& request_json, http::Reply& reply) {
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

Task<void> RequestHandler::handle_request(uint32_t request_id, commands::RpcApiTable::HandleMethod handler, const nlohmann::json& request_json, http::Reply& reply) {
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

Task<void> RequestHandler::handle_request(commands::RpcApiTable::HandleStream handler, const nlohmann::json& request_json) {
    try {
        SocketWriter socket_writer(socket_);
        ChunksWriter chunks_writer(socket_writer, 0x1FFF);
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

RequestHandler::AuthorizationResult RequestHandler::is_request_authorized(const http::Request& request) {
    if (!jwt_secret_.has_value() || (*jwt_secret_).empty()) {
        return {};
    }

    const auto it = std::find_if(request.headers.begin(), request.headers.end(), [&](const Header& h) {
        return h.name == "Authorization";
    });

    if (it == request.headers.end()) {
        SILK_ERROR << "JWT request without Authorization field";
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

//! The number of HTTP headers added when Cross-Origin Resource Sharing (CORS) is enabled.
static constexpr size_t kCorsNumHeaders{4};

Task<void> RequestHandler::do_write(Reply& reply) {
    try {
        SILK_DEBUG << "RequestHandler::do_write reply: " << reply.content;

        reply.headers.reserve(allowed_origins_.empty() ? 2 : 2 + kCorsNumHeaders);
        reply.headers.emplace_back(http::Header{"Content-Length", std::to_string(reply.content.size())});
        reply.headers.emplace_back(http::Header{"Content-Type", "application/json"});

        set_cors(reply.headers);

        const auto bytes_transferred = co_await boost::asio::async_write(socket_, reply.to_buffers(), boost::asio::use_awaitable);
        SILK_TRACE << "RequestHandler::do_write bytes_transferred: " << bytes_transferred;
    } catch (const boost::system::system_error& se) {
        std::rethrow_exception(std::make_exception_ptr(se));
    } catch (const std::exception& e) {
        std::rethrow_exception(std::make_exception_ptr(e));
    }
}

Task<void> RequestHandler::write_headers() {
    try {
        std::vector<http::Header> headers;
        headers.reserve(allowed_origins_.empty() ? 2 : 2 + kCorsNumHeaders);
        headers.emplace_back(http::Header{"Content-Type", "application/json"});
        headers.emplace_back(http::Header{"Transfer-Encoding", "chunked"});

        set_cors(headers);

        auto buffers = http::to_buffers(StatusType::ok, headers);

        const auto bytes_transferred = co_await boost::asio::async_write(socket_, buffers, boost::asio::use_awaitable);

        SILK_TRACE << "RequestHandler::write_headers bytes_transferred: " << bytes_transferred;
    } catch (const std::system_error& se) {
        std::rethrow_exception(std::make_exception_ptr(se));
    } catch (const std::exception& e) {
        std::rethrow_exception(std::make_exception_ptr(e));
    }
}

void RequestHandler::set_cors(std::vector<Header>& headers) {
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

}  // namespace silkworm::rpc::http
