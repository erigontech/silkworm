// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <map>
#include <memory>
#include <string>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/thread_pool.hpp>
#include <tl/expected.hpp>

#include <silkworm/rpc/commands/rpc_api.hpp>
#include <silkworm/rpc/commands/rpc_api_table.hpp>
#include <silkworm/rpc/common/interface_log.hpp>
#include <silkworm/rpc/json_rpc/validator.hpp>
#include <silkworm/rpc/transport/request_handler.hpp>
#include <silkworm/rpc/transport/stream_writer.hpp>

namespace silkworm::rpc::json_rpc {

class RequestHandler : public rpc::RequestHandler {
  public:
    RequestHandler(StreamWriter* stream_writer,
                   commands::RpcApi& rpc_api,
                   const commands::RpcApiTable& rpc_api_table,
                   InterfaceLogSettings ifc_log_settings = {});
    ~RequestHandler() override = default;

    RequestHandler(const RequestHandler&) = delete;
    RequestHandler& operator=(const RequestHandler&) = delete;

    Task<std::optional<std::string>> handle(const std::string& request, uint64_t request_id) override;

  protected:
    Task<bool> handle_request_and_create_reply(const nlohmann::json& request_json, std::string& response, uint64_t request_id);

  private:
    nlohmann::json prevalidate_and_parse(const std::string& request);
    ValidationResult is_valid_jsonrpc(const nlohmann::json& request_json);

    Task<void> handle_request(
        commands::RpcApiTable::HandleMethod handler,
        const nlohmann::json& request_json,
        std::string& response);
    Task<void> handle_request(
        commands::RpcApiTable::HandleMethodGlaze handler,
        const nlohmann::json& request_json,
        std::string& response);
    Task<void> handle_request(commands::RpcApiTable::HandleStream handler, const nlohmann::json& request_json, uint64_t request_id);

    StreamWriter* stream_writer_;

    commands::RpcApi& rpc_api_;

    const commands::RpcApiTable& rpc_api_table_;

    Validator json_rpc_validator_;

    std::shared_ptr<InterfaceLog> ifc_log_;
};

}  // namespace silkworm::rpc::json_rpc
