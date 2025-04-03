// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/common/application_info.hpp>
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
#include <silkworm/rpc/common/worker_pool.hpp>

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
    explicit RpcApi(
        boost::asio::io_context& ioc,
        WorkerPool& workers,
        ApplicationInfo build_info = {})
        : EthereumRpcApi{ioc, workers},
          NetRpcApi{ioc},
          AdminRpcApi{ioc},
          Web3RpcApi{ioc},
          DebugRpcApi{ioc, workers},
          ParityRpcApi{ioc, workers},
          ErigonRpcApi{ioc, workers},
          TraceRpcApi{ioc, workers},
          EngineRpcApi(ioc, std::move(build_info)),
          TxPoolRpcApi(ioc),
          OtsRpcApi{ioc, workers} {}

    ~RpcApi() override = default;

    RpcApi(const RpcApi&) = delete;
    RpcApi& operator=(const RpcApi&) = delete;
    RpcApi(RpcApi&&) = default;

    friend class RpcApiTable;
    friend class silkworm::rpc::json_rpc::RequestHandler;
};

}  // namespace silkworm::rpc::commands
