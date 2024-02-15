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

#include <memory>

#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>

#include <silkworm/rpc/commands/admin_api.hpp>
#include <silkworm/rpc/commands/debug_api.hpp>
#include <silkworm/rpc/commands/engine_api.hpp>
#include <silkworm/rpc/commands/erigon_api.hpp>
#include <silkworm/rpc/commands/eth_api.hpp>
#include <silkworm/rpc/commands/net_api.hpp>
#include <silkworm/rpc/commands/ots_api.hpp>
#include <silkworm/rpc/commands/parity_api.hpp>
#include <silkworm/rpc/commands/trace_api.hpp>
#include <silkworm/rpc/commands/txpool_api.hpp>
#include <silkworm/rpc/commands/web3_api.hpp>

namespace silkworm::rpc::json_rpc {
class RequestHandler;
}

namespace silkworm::rpc::commands {

class RpcApiTable;

class RpcApi : protected EthereumRpcApi,
               NetRpcApi,
               AdminRpcApi,
               Web3RpcApi,
               DebugRpcApi,
               ParityRpcApi,
               ErigonRpcApi,
               TraceRpcApi,
               EngineRpcApi,
               TxPoolRpcApi,
               OtsRpcApi {
  public:
    explicit RpcApi(boost::asio::io_context& io_context, boost::asio::thread_pool& workers)
        : EthereumRpcApi{io_context, workers},
          NetRpcApi{io_context},
          AdminRpcApi{io_context},
          Web3RpcApi{io_context},
          DebugRpcApi{io_context, workers},
          ParityRpcApi{io_context},
          ErigonRpcApi{io_context},
          TraceRpcApi{io_context, workers},
          EngineRpcApi(io_context),
          TxPoolRpcApi(io_context),
          OtsRpcApi{io_context, workers} {}

    ~RpcApi() override = default;

    RpcApi(const RpcApi&) = delete;
    RpcApi& operator=(const RpcApi&) = delete;

    friend class RpcApiTable;
    friend class silkworm::rpc::json_rpc::RequestHandler;
};

}  // namespace silkworm::rpc::commands
