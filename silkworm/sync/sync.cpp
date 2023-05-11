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

#include <boost/asio/experimental/awaitable_operators.hpp>

#include "engine_api_backend.hpp"
#include "sync_pos.hpp"
#include "sync_pow.hpp"

namespace silkworm::chainsync {

Sync::Sync(boost::asio::io_context& io_context,
           mdbx::env& chaindata_env,
           execution::Client& execution,
           const std::shared_ptr<silkworm::sentry::api::api_common::SentryClient>& sentry_client,
           const ChainConfig& config,
           const EngineRpcSettings& rpc_settings)
    : sync_sentry_client_{io_context, sentry_client},
      block_exchange_{sync_sentry_client_, db::ROAccess{chaindata_env}, config} {
    // If terminal total difficulty is present in chain config, the network will use Proof-of-Stake sooner or later
    if (config.terminal_total_difficulty) {
        // Configure and activate the Execution Layer Engine API RPC server
        rpc::DaemonSettings engine_rpc_settings{
            .http_port = "",  // no need for Ethereum JSON RPC end-point
            .engine_port = rpc_settings.engine_end_point,
            .api_spec = kDefaultEth2ApiSpec,
            .target = rpc_settings.backend_kv_address,
            .num_contexts = 1,  // single-client so just one scheduler should be OK
            .num_workers = 1,   // single-client so just one worker should be OK
            .log_verbosity = rpc_settings.log_verbosity,
            .wait_mode = concurrency::WaitMode::blocking,  // single-client so no need to play w/ strategies
            .jwt_secret_filename = rpc_settings.jwt_secret_filename,
        };
        engine_rpc_server_ = std::make_unique<rpc::Daemon>(engine_rpc_settings);

        // Create the synchronization algorithm based on Casper + LMD-GHOST, i.e. PoS
        auto pos_sync = std::make_unique<PoSSync>(block_exchange_, execution);
        engine_rpc_server_->add_backend_service(std::make_unique<EngineApiBackend>(*pos_sync));
        chain_sync_ = std::move(pos_sync);
    } else {
        // Create the synchronization algorithm based on GHOST, i.e. PoW
        chain_sync_ = std::make_unique<PoWSync>(block_exchange_, execution);
    }
}

boost::asio::awaitable<void> Sync::async_run() {
    using namespace boost::asio::experimental::awaitable_operators;
    if (engine_rpc_server_) {
        auto engine_rpc_server_run = [this]() {
            engine_rpc_server_->start();
            engine_rpc_server_->join();
        };
        auto engine_rpc_server_stop = [this]() {
            engine_rpc_server_->stop();
        };
        return sync_sentry_client_.async_run() &&
               block_exchange_.async_run() &&
               chain_sync_->async_run() &&
               concurrency::async_thread(std::move(engine_rpc_server_run), std::move(engine_rpc_server_stop));
    } else {
        return sync_sentry_client_.async_run() && block_exchange_.async_run() && chain_sync_->async_run();
    }
}

}  // namespace silkworm::chainsync
