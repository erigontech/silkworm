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

#include <boost/asio/thread_pool.hpp>

#include <silkworm/silkrpc/commands/admin_api.hpp>
#include <silkworm/silkrpc/commands/debug_api.hpp>
#include <silkworm/silkrpc/commands/engine_api.hpp>
#include <silkworm/silkrpc/commands/erigon_api.hpp>
#include <silkworm/silkrpc/commands/eth_api.hpp>
#include <silkworm/silkrpc/commands/net_api.hpp>
#include <silkworm/silkrpc/commands/ots_api.hpp>
#include <silkworm/silkrpc/commands/parity_api.hpp>
#include <silkworm/silkrpc/commands/trace_api.hpp>
#include <silkworm/silkrpc/commands/txpool_api.hpp>
#include <silkworm/silkrpc/commands/web3_api.hpp>

namespace silkworm::http {
class RequestHandler;
}

namespace silkworm::rpc::commands {

class RpcApiTable;

class RpcApi : protected EthereumRpcApi, NetRpcApi, AdminRpcApi, Web3RpcApi, DebugRpcApi, ParityRpcApi, ErigonRpcApi, TraceRpcApi, EngineRpcApi, TxPoolRpcApi, OtsRpcApi {
  public:
    explicit RpcApi(Context& context, boost::asio::thread_pool& workers)
        : EthereumRpcApi{context, workers},
          NetRpcApi{context.backend()},
          AdminRpcApi{context.backend()},
          Web3RpcApi{context},
          DebugRpcApi{context, workers},
          ParityRpcApi{context},
          ErigonRpcApi{context},
          TraceRpcApi{context, workers},
          EngineRpcApi(context.database(), context.backend()),
          TxPoolRpcApi(context),
          OtsRpcApi{context, workers} {}

    ~RpcApi() override = default;

    RpcApi(const RpcApi&) = delete;
    RpcApi& operator=(const RpcApi&) = delete;

    friend class RpcApiTable;
    friend class silkworm::http::RequestHandler;
};

}  // namespace silkworm::rpc::commands
