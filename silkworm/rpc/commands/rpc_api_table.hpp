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

#include <silkworm/infra/concurrency/task.hpp>

#include <nlohmann/json.hpp>

#include <silkworm/rpc/commands/rpc_api.hpp>
#include <silkworm/rpc/json/stream.hpp>

namespace silkworm::rpc::commands {

class RpcApiTable {
  public:
    using HandleMethod = Task<void> (RpcApi::*)(const nlohmann::json&, nlohmann::json&);
    using HandleMethodGlaze = Task<void> (RpcApi::*)(const nlohmann::json&, std::string&);
    using HandleStream = Task<void> (RpcApi::*)(const nlohmann::json&, json::Stream&);

    explicit RpcApiTable(const std::string& api_spec);

    RpcApiTable(const RpcApiTable&) = delete;
    RpcApiTable& operator=(const RpcApiTable&) = delete;
    RpcApiTable(RpcApiTable&&) = default;

    std::optional<HandleMethod> find_json_handler(const std::string& method) const;
    std::optional<HandleMethodGlaze> find_json_glaze_handler(const std::string& method) const;
    std::optional<HandleStream> find_stream_handler(const std::string& method) const;

  private:
    void build_handlers(const std::string& api_spec);
    void add_handlers(const std::string& api_namespace);
    void add_admin_handlers();
    void add_debug_handlers();
    void add_eth_handlers();
    void add_net_handlers();
    void add_parity_handlers();
    void add_erigon_handlers();
    void add_trace_handlers();
    void add_web3_handlers();
    void add_engine_handlers();
    void add_txpool_handlers();
    void add_ots_handlers();

    std::map<std::string, HandleMethod> method_handlers_;
    std::map<std::string, HandleMethodGlaze> method_handlers_glaze_;
    std::map<std::string, HandleStream> stream_handlers_;
};

}  // namespace silkworm::rpc::commands
