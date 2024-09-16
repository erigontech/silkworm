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

#include "node.hpp"

#include <utility>

#include <boost/asio/io_context.hpp>

#include <silkworm/db/snapshot_sync.hpp>
#include <silkworm/execution/api/active_direct_service.hpp>
#include <silkworm/execution/grpc/server/server.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/os.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/node/backend/ethereum_backend.hpp>
#include <silkworm/node/resource_usage.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>
#include <silkworm/node/stagedsync/stages/stage_bodies.hpp>
#include <silkworm/node/stagedsync/stages/stage_bodies_factory.hpp>
#include <silkworm/sync/sync.hpp>

#include "backend_kv_server.hpp"

namespace silkworm::node {

//! Custom stack size for thread running block execution on EVM
constexpr uint64_t kExecutionThreadStackSize{16'777'216};  // 16MiB

using SentryClientPtr = std::shared_ptr<sentry::api::SentryClient>;

class NodeImpl final {
  public:
    NodeImpl(
        boost::asio::any_io_executor executor,
        Settings& settings,
        SentryClientPtr sentry_client,
        chainsync::EngineRpcSettings sync_engine_rpc_settings,
        mdbx::env chaindata_env);

    NodeImpl(const NodeImpl&) = delete;
    NodeImpl& operator=(const NodeImpl&) = delete;

    std::shared_ptr<sentry::api::SentryClient> sentry_client() { return sentry_client_; }

    Task<void> run();
    Task<void> run_tasks();
    Task<void> wait_for_setup();

    BlockNum last_pre_validated_block() const { return chain_sync_.last_pre_validated_block(); }

  private:
    Task<void> start_execution_server();
    Task<void> start_backend_kv_grpc_server();
    Task<void> start_resource_usage_log();
    Task<void> start_execution_log_timer();

    Settings& settings_;

    mdbx::env chaindata_env_;

    //! The execution layer server engine
    boost::asio::io_context execution_context_;
    stagedsync::ExecutionEngine execution_engine_;
    std::shared_ptr<execution::api::ActiveDirectService> execution_service_;
    execution::grpc::server::Server execution_server_;
    execution::api::DirectClient execution_direct_client_;

    db::SnapshotSync snapshot_sync_;

    SentryClientPtr sentry_client_;

    std::unique_ptr<EthereumBackEnd> backend_;
    std::unique_ptr<BackEndKvServer> backend_kv_rpc_server_;

    // ChainSync: the chain synchronization process based on the consensus protocol
    chainsync::Sync chain_sync_;

    ResourceUsageLog resource_usage_log_;

    std::unique_ptr<snapshots::bittorrent::BitTorrentClient> bittorrent_client_;
};

static auto make_execution_server_settings() {
    return rpc::ServerSettings{
        .address_uri = "localhost:9092",
        .context_pool_settings = {.num_contexts = 1},  // just one execution context
    };
}

static stagedsync::BodiesStageFactory make_bodies_stage_factory(
    const ChainConfig& chain_config,
    const NodeImpl& node) {
    return [&](stagedsync::SyncContext* sync_context) {
        return std::make_unique<stagedsync::BodiesStage>(
            sync_context,
            chain_config,
            [&node]() { return node.last_pre_validated_block(); });
    };
};

NodeImpl::NodeImpl(
    boost::asio::any_io_executor executor,
    Settings& settings,
    SentryClientPtr sentry_client,
    chainsync::EngineRpcSettings sync_engine_rpc_settings,
    mdbx::env chaindata_env)
    : settings_{settings},
      chaindata_env_{std::move(chaindata_env)},
      execution_engine_{
          execution_context_,
          settings_,
          make_bodies_stage_factory(*settings_.chain_config, *this),
          db::RWAccess{chaindata_env_},
      },
      execution_service_{std::make_shared<execution::api::ActiveDirectService>(execution_engine_, execution_context_)},
      execution_server_{make_execution_server_settings(), execution_service_},
      execution_direct_client_{execution_service_},
      snapshot_sync_{settings.snapshot_settings, settings.chain_config->chain_id, chaindata_env_, settings_.data_directory->temp().path(), execution_engine_.stage_scheduler()},
      sentry_client_{std::move(sentry_client)},
      chain_sync_{
          std::move(executor),
          chaindata_env_,
          execution_direct_client_,
          sentry_client_,
          *settings.chain_config,
          /* use_preverified_hashes = */ true,
          std::move(sync_engine_rpc_settings),
      },
      resource_usage_log_{*settings_.data_directory} {
    backend_ = std::make_unique<EthereumBackEnd>(settings_, &chaindata_env_, sentry_client_);
    backend_->set_node_name(settings_.build_info.node_name);
    backend_kv_rpc_server_ = std::make_unique<BackEndKvServer>(settings_.server_settings, *backend_);
    bittorrent_client_ = std::make_unique<snapshots::bittorrent::BitTorrentClient>(settings_.snapshot_settings.bittorrent_settings);
}

Task<void> NodeImpl::wait_for_setup() {
    co_await snapshot_sync_.wait_for_setup();
}

Task<void> NodeImpl::run() {
    using namespace concurrency::awaitable_wait_for_all;

    co_await (run_tasks() && snapshot_sync_.run());
}

Task<void> NodeImpl::run_tasks() {
    using namespace concurrency::awaitable_wait_for_all;

    co_await wait_for_setup();

    co_await (
        start_execution_server() &&
        start_resource_usage_log() &&
        start_execution_log_timer() &&
        chain_sync_.async_run() &&
        start_backend_kv_grpc_server());
}

Task<void> NodeImpl::start_execution_server() {
    // Thread running block execution requires custom stack size because of deep EVM call stacks
    if (settings_.execution_server_enabled) {
        co_await execution_server_.async_run(/*stack_size=*/kExecutionThreadStackSize);
    } else {
        co_await execution_service_->async_run("exec-engine", /*stack_size=*/kExecutionThreadStackSize);
    }
}

Task<void> NodeImpl::start_backend_kv_grpc_server() {
    auto run = [this]() {
        backend_kv_rpc_server_->build_and_start();
        backend_kv_rpc_server_->join();
    };
    auto stop = [this]() {
        backend_kv_rpc_server_->shutdown();
    };
    co_await concurrency::async_thread(std::move(run), std::move(stop), "bekv-server");
}

Task<void> NodeImpl::start_resource_usage_log() {
    return resource_usage_log_.run();
}

Task<void> NodeImpl::start_execution_log_timer() {
    // Run Asio context in settings for execution timers // TODO(canepat) we need a better solution
    using asio_guard_type = boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;
    auto asio_guard = std::make_unique<asio_guard_type>(settings_.asio_context.get_executor());

    auto run = [this] {
        log::set_thread_name("ctx-log-tmr");
        log::Trace("Asio Timers", {"state", "started"});
        settings_.asio_context.run();
        log::Trace("Asio Timers", {"state", "stopped"});
    };
    auto stop = [&asio_guard] { asio_guard.reset(); };
    co_await silkworm::concurrency::async_thread(std::move(run), std::move(stop), "ctx-log-tmr");
}

Node::Node(
    boost::asio::any_io_executor executor,
    Settings& settings,
    SentryClientPtr sentry_client,
    chainsync::EngineRpcSettings sync_engine_rpc_settings,
    mdbx::env chaindata_env)
    : p_impl_(std::make_unique<NodeImpl>(
          std::move(executor),
          settings,
          std::move(sentry_client),
          std::move(sync_engine_rpc_settings),
          std::move(chaindata_env))) {}

// Must be here (not in header) because NodeImpl size is necessary for std::unique_ptr in PIMPL idiom
Node::~Node() = default;

Task<void> Node::run() {
    return p_impl_->run();
}

Task<void> Node::wait_for_setup() {
    return p_impl_->wait_for_setup();
}

}  // namespace silkworm::node
