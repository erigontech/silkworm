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

#include "request_handler.hpp"

#include <algorithm>
#include <sstream>

#include <nlohmann/json.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/commands/eth_api.hpp>
#include <silkworm/rpc/common/clock_time.hpp>
#include <silkworm/rpc/http/header.hpp>
#include <silkworm/rpc/types/writer.hpp>

namespace silkworm::rpc::http {

Task<void> RequestHandler::handle(const std::string& content) {
    auto start = clock_time::now();
    std::string response;
    bool send_reply{true};
    nlohmann::json request_json;
    try {
        request_json = nlohmann::json::parse(content);
        if (request_json.is_object()) {
            if (!is_valid_jsonrpc(request_json)) {
                response = make_json_error(0, -32600, "invalid request").dump() + "\n";
            } else {
                send_reply = co_await handle_request_and_create_reply(request_json, response);
                response += "\n";
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
                    std::string single_reply;
                    send_reply = co_await handle_request_and_create_reply(item.value(), single_reply);
                    batch_reply_content << single_reply;
                }
            }
            batch_reply_content << "]\n";

            response = batch_reply_content.str();
        }
    } catch (const nlohmann::json::exception& e) {
        SILK_ERROR << "Connection::do_read json_parse: " << e.what();
        response = make_json_error(0, -32600, "invalid request").dump() + "\n";
        send_reply = true;
    }

    if (send_reply) {
        co_await channel_->write_rsp(response);
    }
    SILK_TRACE << "handle HTTP request t=" << clock_time::since(start) << "ns";
}

bool RequestHandler::is_valid_jsonrpc(const nlohmann::json& /* request_json */) {
    // auto validation_result = json_rpc_validator_.validate(request_json);
    // return validation_result.is_valid;
    return true;
}

Task<bool> RequestHandler::handle_request_and_create_reply(const nlohmann::json& request_json, std::string& response) {
    if (!request_json.contains("method")) {
        response = make_json_error(request_json, -32600, "invalid request").dump();
        co_return true;
    }

    const auto method = request_json["method"].get<std::string>();
    if (method.empty()) {
        response = make_json_error(request_json, -32600, "invalid request").dump();
        co_return true;
    }

    // Dispatch JSON handlers in this order: 1) glaze JSON 2) nlohmann JSON 3) JSON streaming
    const auto json_glaze_handler = rpc_api_table_.find_json_glaze_handler(method);
    if (json_glaze_handler) {
        SILK_TRACE << "--> handle RPC request: " << method;
        co_await handle_request(*json_glaze_handler, request_json, response);
        SILK_TRACE << "<-- handle RPC request: " << method;
        co_return true;
    }
    const auto json_handler = rpc_api_table_.find_json_handler(method);
    if (json_handler) {
        SILK_TRACE << "--> handle RPC request: " << method;
        co_await handle_request(*json_handler, request_json, response);
        SILK_TRACE << "<-- handle RPC request: " << method;
        co_return true;
    }
    const auto stream_handler = rpc_api_table_.find_stream_handler(method);
    if (stream_handler) {
        SILK_TRACE << "--> handle RPC stream request: " << method;
        co_await handle_request(*stream_handler, request_json);
        SILK_TRACE << "<-- handle RPC stream request: " << method;
        co_return false;
    }

    response = make_json_error(request_json, -32601, "the method " + method + " does not exist/is not available").dump();

    co_return true;
}

Task<void> RequestHandler::handle_request(commands::RpcApiTable::HandleMethodGlaze handler, const nlohmann::json& request_json, std::string& response) {
    try {
        std::string reply_json;
        reply_json.reserve(2048);
        co_await (rpc_api_.*handler)(request_json, reply_json);
        response = std::move(reply_json);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what();
        response = make_json_error(request_json, 100, e.what()).dump();
    } catch (...) {
        SILK_ERROR << "unexpected exception";
        response = make_json_error(request_json, 100, "unexpected exception").dump();
    }

    co_return;
}

Task<void> RequestHandler::handle_request(commands::RpcApiTable::HandleMethod handler, const nlohmann::json& request_json, std::string& response) {
    try {
        nlohmann::json reply_json;
        co_await (rpc_api_.*handler)(request_json, reply_json);
        response = reply_json.dump(
            /*indent=*/-1, /*indent_char=*/' ', /*ensure_ascii=*/false, nlohmann::json::error_handler_t::replace);

    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what();
        response = make_json_error(request_json, 100, e.what()).dump();
    } catch (...) {
        SILK_ERROR << "unexpected exception";
        response = make_json_error(request_json, 100, "unexpected exception").dump();
    }

    co_return;
}

Task<void> RequestHandler::handle_request(commands::RpcApiTable::HandleStream handler, const nlohmann::json& request_json) {
    auto io_executor = co_await boost::asio::this_coro::executor;

    try {
        co_await channel_->open_stream();
        ChunkWriter chunk_writer(*channel_);
        json::Stream stream(io_executor, chunk_writer);

        try {
            co_await (rpc_api_.*handler)(request_json, stream);
        } catch (const std::exception& e) {
            SILK_ERROR << "exception: " << e.what();
            const auto error = make_json_error(request_json, 100, e.what());
            stream.write_json(error);
        } catch (...) {
            SILK_ERROR << "unexpected exception";
            const auto error = make_json_error(request_json, 100, "unexpected exception");
            stream.write_json(error);
        }
        co_await stream.close();
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what();
    }

    co_return;
}

}  // namespace silkworm::rpc::http
