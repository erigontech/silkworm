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
#include <optional>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/db/datastore/mdbx/mdbx.hpp>
#include <silkworm/execution/api/client.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/rpc/common/interface_log.hpp>
#include <silkworm/rpc/daemon.hpp>
#include <silkworm/sentry/api/common/sentry_client.hpp>

#include "block_exchange.hpp"
#include "chain_sync.hpp"
#include "sentry_client.hpp"
#include "settings.hpp"

namespace silkworm::chainsync {

class Sync {
  public:
    Sync(const boost::asio::any_io_executor& executor,
         mdbx::env chaindata_env,
         execution::api::Client& execution,
         const std::shared_ptr<silkworm::sentry::api::SentryClient>& sentry_client,
         const ChainConfig& config,
         bool use_preverified_hashes,
         const EngineRpcSettings& rpc_settings = {});

    Sync(const Sync&) = delete;
    Sync& operator=(const Sync&) = delete;

    Task<void> async_run();

    BlockNum last_pre_validated_block() const;

  private:
    Task<void> run_tasks();
    Task<void> start_sync_sentry_client();
    Task<void> start_block_exchange();
    Task<void> start_chain_sync();
    Task<void> start_engine_rpc_server();

    //! The Sentry synchronous (i.e. blocking) client used by BlockExchange
    SentryClient sync_sentry_client_;

    //! The gateway for exchanging blocks with peers
    BlockExchange block_exchange_;

    //! The chain synchronization algorithm
    std::shared_ptr<ChainSync> chain_sync_;

    //! The Execution Layer Engine API RPC server
    std::unique_ptr<rpc::Daemon> engine_rpc_server_;
};

}  // namespace silkworm::chainsync
