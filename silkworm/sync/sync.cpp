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

#include "sync.hpp"

#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>

#include "engine_api_backend.hpp"
#include "sync_pos.hpp"
#include "sync_pow.hpp"

namespace silkworm::chainsync {

Sync::Sync(const boost::asio::any_io_executor& executor,
           mdbx::env chaindata_env,
           execution::Client& execution,
           const std::shared_ptr<silkworm::sentry::api::SentryClient>& sentry_client,
           const ChainConfig& config,
           const EngineRpcSettings& rpc_settings)
    : sync_sentry_client_{executor, sentry_client},
      block_exchange_{sync_sentry_client_, db::ROAccess{chaindata_env}, config} {
    // If terminal total difficulty is present in chain config, the network will use Proof-of-Stake sooner or later
    if (config.terminal_total_difficulty) {
        // Configure and activate the Execution Layer Engine API RPC server
        rpc::DaemonSettings engine_rpc_settings{
            .log_settings = {
                .log_verbosity = rpc_settings.log_verbosity,
            },
            .context_pool_settings{
                .num_contexts = 1,                             // single-client so just one scheduler is OK
                .wait_mode = concurrency::WaitMode::blocking,  // single-client so no need to play w/ strategies
            },
            .eth_end_point = "",  // no need for Ethereum JSON RPC end-point
            .engine_end_point = rpc_settings.engine_end_point,
            .eth_api_spec = kDefaultEth2ApiSpec,
            .private_api_addr = rpc_settings.private_api_addr,
            .num_workers = 1,  // single-client so just one worker should be OK
            .jwt_secret_file = rpc_settings.jwt_secret_file,
        };
        engine_rpc_server_ = std::make_unique<rpc::Daemon>(engine_rpc_settings, chaindata_env);

        // Create the synchronization algorithm based on Casper + LMD-GHOST, i.e. PoS
        auto pos_sync = std::make_unique<PoSSync>(block_exchange_, execution);
        std::vector<std::unique_ptr<rpc::ethbackend::BackEnd>> backends;
        backends.push_back(std::make_unique<EngineApiBackend>(*pos_sync));  // just one PoS-based Engine backend
        engine_rpc_server_->add_backend_services(std::move(backends));
        chain_sync_ = std::move(pos_sync);
    } else {
        // Create the synchronization algorithm based on GHOST, i.e. PoW
        chain_sync_ = std::make_unique<PoWSync>(block_exchange_, execution);
    }
}

void Sync::force_pow(execution::Client& execution) {
    chain_sync_ = std::make_unique<PoWSync>(block_exchange_, execution);
    engine_rpc_server_.reset();
}

Task<void> Sync::async_run() {
    using namespace concurrency::awaitable_wait_for_all;
    return (run_tasks() && start_engine_rpc_server());
}

Task<void> Sync::run_tasks() {
    using namespace concurrency::awaitable_wait_for_all;
    co_await (start_sync_sentry_client() && start_block_exchange() && start_chain_sync());
}

Task<void> Sync::start_sync_sentry_client() {
    return sync_sentry_client_.async_run();
}

Task<void> Sync::start_block_exchange() {
    return block_exchange_.async_run("block-exchg");
}

Task<void> Sync::start_chain_sync() {
    if (!engine_rpc_server_) {
        return chain_sync_->async_run();
    }

    // The ChainSync async loop *must* run onto the Engine RPC server unique execution context
    // This is *strictly* required by the current design assumptions in PoSSync
    auto& engine_rpc_ioc = engine_rpc_server_->context_pool().next_io_context();
    return boost::asio::co_spawn(engine_rpc_ioc, chain_sync_->async_run(), boost::asio::use_awaitable);
}

Task<void> Sync::start_engine_rpc_server() {
    if (engine_rpc_server_) {
        auto engine_rpc_server_run = [this]() {
            engine_rpc_server_->start();
            engine_rpc_server_->join();
        };
        auto engine_rpc_server_stop = [this]() {
            engine_rpc_server_->stop();
        };
        co_await concurrency::async_thread(std::move(engine_rpc_server_run),
                                           std::move(engine_rpc_server_stop),
                                           "eng-api-srv");
    }
}

}  // namespace silkworm::chainsync
