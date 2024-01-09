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

#include <map>
#include <memory>
#include <string>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/thread_pool.hpp>
#include <tl/expected.hpp>

#include <silkworm/rpc/commands/rpc_api.hpp>
#include <silkworm/rpc/commands/rpc_api_table.hpp>
#include <silkworm/rpc/http/channel_writer.hpp>

namespace silkworm::rpc::http {

class RequestHandler {
  public:
    RequestHandler(ChannelWriter* channel_writer,
                   commands::RpcApi& rpc_api,
                   const commands::RpcApiTable& rpc_api_table)
        : rpc_api_{rpc_api},
          channel_writer_{channel_writer},
          rpc_api_table_(rpc_api_table) {}

    RequestHandler(const RequestHandler&) = delete;
    virtual ~RequestHandler() = default;
    RequestHandler& operator=(const RequestHandler&) = delete;

    Task<void> handle(const std::string& request);

  protected:
    Task<bool> handle_request_and_create_reply(const nlohmann::json& request_json, ChannelWriter::Response& response);

  private:
    Task<void> handle_request(
        commands::RpcApiTable::HandleMethod handler,
        const nlohmann::json& request_json,
        ChannelWriter::Response& response);
    Task<void> handle_request(
        commands::RpcApiTable::HandleMethodGlaze handler,
        const nlohmann::json& request_json,
        ChannelWriter::Response& response);
    Task<void> handle_request(commands::RpcApiTable::HandleStream handler, const nlohmann::json& request_json);

    commands::RpcApi& rpc_api_;

    ChannelWriter* channel_writer_;

    const commands::RpcApiTable& rpc_api_table_;
};

}  // namespace silkworm::rpc::http
