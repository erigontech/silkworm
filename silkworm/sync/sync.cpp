// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "sync.hpp"

#include <utility>

#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>

#include "sync_pos.hpp"
#include "sync_pow.hpp"

namespace silkworm::chainsync {

Sync::Sync(const boost::asio::any_io_executor& executor,
           db::DataStoreRef data_store,
           execution::api::Client& execution,
           const std::shared_ptr<sentry::api::SentryClient>& sentry_client,
           const ChainConfig& config,
           bool use_preverified_hashes,
           const EngineRpcSettings& rpc_settings)
    : sync_sentry_client_{executor, sentry_client},
      block_exchange_{data_store, sync_sentry_client_, config, use_preverified_hashes} {
    // If terminal total difficulty is present in chain config, the network will use Proof-of-Stake sooner or later
    if (config.terminal_total_difficulty.has_value()) {
        // Configure and activate the Execution Layer Engine API RPC server
        rpc::DaemonSettings engine_rpc_settings{
            .log_settings = {
                .log_verbosity = rpc_settings.log_verbosity,
            },
            .engine_ifc_log_settings = rpc_settings.engine_ifc_log_settings,
            .context_pool_settings{
                // single-client so just one scheduler is OK
                .num_contexts = 1,
            },
            .eth_end_point = "",  // no need for Ethereum JSON RPC end-point
            .engine_end_point = rpc_settings.engine_end_point,
            .eth_api_spec = kDefaultEth2ApiSpec,
            .private_api_addr = rpc_settings.private_api_addr,
            .num_workers = 1,  // single-client so just one worker should be OK
            .jwt_secret_file = rpc_settings.jwt_secret_file,
        };
        engine_rpc_server_ = std::make_unique<rpc::Daemon>(engine_rpc_settings, std::make_optional(config), data_store);

        // Create the synchronization algorithm based on Casper + LMD-GHOST, i.e. PoS
        auto pos_sync = std::make_shared<PoSSync>(block_exchange_, execution);
        std::vector<std::shared_ptr<rpc::engine::ExecutionEngine>> engines{pos_sync};  // just one PoS-based Engine backend
        engine_rpc_server_->add_execution_services(engines);
        chain_sync_ = std::move(pos_sync);
    } else {
        // Create the synchronization algorithm based on GHOST, i.e. PoW
        chain_sync_ = std::make_shared<PoWSync>(block_exchange_, execution);
    }
}

BlockNum Sync::last_pre_validated_block() const {
    return block_exchange_.last_pre_validated_block();
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
    auto& ioc = engine_rpc_server_->context_pool().next_ioc();
    return boost::asio::co_spawn(ioc, chain_sync_->async_run(), boost::asio::use_awaitable);
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
