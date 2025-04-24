// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "request_handler.hpp"

#include <algorithm>
#include <sstream>

#include <nlohmann/json.hpp>

#include <silkworm/infra/common/clock_time.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/commands/eth_api.hpp>
#include <silkworm/rpc/protocol/errors.hpp>
#include <silkworm/rpc/transport/stream_writer.hpp>

namespace silkworm::rpc::json_rpc {

RequestHandler::RequestHandler(StreamWriter* stream_writer,
                               commands::RpcApi& rpc_api,
                               const commands::RpcApiTable& rpc_api_table,
                               InterfaceLogSettings ifc_log_settings)
    : stream_writer_{stream_writer},
      rpc_api_{rpc_api},
      rpc_api_table_{rpc_api_table},
      ifc_log_{ifc_log_settings.enabled ? std::make_shared<InterfaceLog>(std::move(ifc_log_settings)) : nullptr} {}

Task<std::optional<std::string>> RequestHandler::handle(const std::string& request) {
    const auto start = clock_time::now();
    std::string response;
    bool return_reply{true};
    try {
        if (ifc_log_) {
            ifc_log_->log_req(request);
        }
        const auto request_json = prevalidate_and_parse(request);
        if (request_json.is_object()) {
            if (const auto valid_result{is_valid_jsonrpc(request_json)}; !valid_result) {
                response = make_json_error(request_json, kInvalidRequest, valid_result.error()).dump() + "\n";
            } else {
                return_reply = co_await handle_request_and_create_reply(request_json, response);
            }
        } else {
            std::stringstream batch_reply_content;
            batch_reply_content << "[";
            int index = 0;
            for (auto& item : request_json.items()) {
                const auto& single_request_json{item.value()};
                if (index++ > 0) {
                    batch_reply_content << ",";
                }

                if (const auto valid_result{is_valid_jsonrpc(single_request_json)}; !valid_result) {
                    batch_reply_content << make_json_error(request_json, kInvalidRequest, valid_result.error()).dump();
                } else {
                    std::string single_reply;
                    return_reply = co_await handle_request_and_create_reply(single_request_json, single_reply);
                    batch_reply_content << single_reply;
                }
            }
            batch_reply_content << "]";
            response = batch_reply_content.str();
        }
    } catch (const nlohmann::json::exception& e) {
        SILK_ERROR << "RequestHandler::handle nlohmann::json::exception: " << e.what();
        response = make_json_error(0, kInvalidRequest, "invalid request").dump() + "\n";
        return_reply = true;
    } catch (const std::runtime_error& re) {
        SILK_ERROR << "RequestHandler::handle runtime error: " << re.what();
        response = make_json_error(0, kMethodNotFound, "invalid request").dump() + "\n";
        return_reply = true;
    }

    if (ifc_log_) {
        ifc_log_->log_rsp(response);
    }
    SILK_TRACE << "handle HTTP request t=" << clock_time::since(start) << "ns";

    if (return_reply) {
        co_return response;
    } else {
        co_return std::nullopt;
    }
}

/**
 * @brief Prevalidate and parse the JSON request. Specifically, it checks for nil characters that are only allowed inside quoted strings.
 * @param request The JSON request
 * @return The parsed JSON request
 */
nlohmann::json RequestHandler::prevalidate_and_parse(const std::string& request) {
    bool inside_quote = false;
    bool previous_char_escape = false;
    for (auto ch : request) {
        if (!inside_quote && ch == 0x0) {
            throw std::runtime_error("invalid request: nil character");
        }

        if (ch == '"' && !previous_char_escape) {
            inside_quote = !inside_quote;
        }
        previous_char_escape = ch == '\\' && !previous_char_escape;
    }

    return nlohmann::json::parse(request);
}

ValidationResult RequestHandler::is_valid_jsonrpc(const nlohmann::json& request_json) {
    return json_rpc_validator_.validate(request_json);
}

Task<bool> RequestHandler::handle_request_and_create_reply(const nlohmann::json& request_json, std::string& response) {
    if (!request_json.contains("method")) {
        response = make_json_error(request_json, kInvalidRequest, "invalid request").dump();
        co_return true;
    }

    const auto method = request_json["method"].get<std::string>();
    if (method.empty()) {
        response = make_json_error(request_json, kInvalidRequest, "invalid request").dump();
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

    response = make_json_error(request_json, kMethodNotFound, "the method " + method + " does not exist/is not available").dump();

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
}

Task<void> RequestHandler::handle_request(commands::RpcApiTable::HandleStream handler, const nlohmann::json& request_json) {
    auto io_executor = co_await boost::asio::this_coro::executor;

    try {
        json::Stream stream(io_executor, *stream_writer_);
        co_await stream.open();

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
}

}  // namespace silkworm::rpc::json_rpc
