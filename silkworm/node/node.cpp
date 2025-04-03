// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "node.hpp"

#include <utility>

#include <boost/asio/io_context.hpp>

#include <silkworm/db/chain_data_init.hpp>
#include <silkworm/db/chain_head.hpp>
#include <silkworm/db/data_store.hpp>
#include <silkworm/db/snapshot_sync.hpp>
#include <silkworm/execution/api/active_direct_service.hpp>
#include <silkworm/execution/api/direct_client.hpp>
#include <silkworm/execution/grpc/server/server.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/os.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/node/backend/ethereum_backend.hpp>
#include <silkworm/node/resource_usage.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>
#include <silkworm/node/stagedsync/stages/stage_bodies.hpp>
#include <silkworm/node/stagedsync/stages/stage_bodies_factory.hpp>
#include <silkworm/node/stagedsync/stages_factory_impl.hpp>
#include <silkworm/sentry/eth/status_data_provider.hpp>
#include <silkworm/sentry/sentry_client_factory.hpp>
#include <silkworm/sync/sync.hpp>

#include "backend_kv_server.hpp"

namespace silkworm::node {

//! Custom stack size for thread running block execution on EVM
static constexpr uint64_t kExecutionThreadStackSize{16'777'216};  // 16MiB

using SentryClientPtr = std::shared_ptr<sentry::api::SentryClient>;

class NodeImpl final {
  public:
    NodeImpl(
        rpc::ClientContextPool& context_pool,
        Settings& settings);

    NodeImpl(const NodeImpl&) = delete;
    NodeImpl& operator=(const NodeImpl&) = delete;

    Task<void> run();
    Task<void> run_tasks();
    Task<void> wait_for_setup();

    BlockNum last_pre_validated_block() const { return chain_sync_.last_pre_validated_block(); }

  private:
    db::DataStoreRef data_store() {
        return data_store_.ref();
    }
    db::DataModelFactory data_model_factory() {
        return db::DataModelFactory{data_store()};
    }
    const ChainConfig& chain_config() const {
        return *settings_.node_settings.chain_config;
    }

    Task<void> run_execution_service();
    Task<void> run_execution_server();
    Task<void> run_backend_kv_grpc_server();
    Task<void> embedded_sentry_run_if_needed();
    Task<void> run_chain_sync();

    Settings& settings_;

    db::DataStore data_store_;

    //! The execution layer server engine
    boost::asio::io_context execution_ioc_;
    stagedsync::ExecutionEngine execution_engine_;
    std::shared_ptr<execution::api::ActiveDirectService> execution_service_;
    execution::grpc::server::Server execution_server_;
    execution::api::DirectClient execution_direct_client_;

    db::SnapshotSync snapshot_sync_;

    sentry::SentryClientFactory::SentryPtrPair sentry_;

    std::unique_ptr<EthereumBackEnd> backend_;
    std::unique_ptr<BackEndKvServer> backend_kv_rpc_server_;

    // ChainSync: the chain synchronization process based on the consensus protocol
    chainsync::Sync chain_sync_;

    ResourceUsageLog resource_usage_log_;

    std::unique_ptr<snapshots::bittorrent::BitTorrentClient> bittorrent_client_;
};

static datastore::kvdb::EnvConfig init_chain_data_db(NodeSettings& node_settings) {
    node_settings.data_directory->deploy();
    node_settings.chain_config = db::chain_data_init(db::ChainDataInitSettings{
        .chaindata_env_config = node_settings.chaindata_env_config,
        .prune_mode = node_settings.prune_mode,
        .network_id = node_settings.network_id,
        .init_if_empty = true,
    });
    return node_settings.chaindata_env_config;
}

static rpc::ServerSettings make_execution_server_settings(const std::optional<std::string>& exec_api_address) {
    return rpc::ServerSettings{
        .address_uri = exec_api_address.value_or("localhost:9092"),
        .context_pool_settings = {.num_contexts = 1},  // just one execution context
    };
}

static chainsync::EngineRpcSettings make_sync_engine_rpc_settings(
    const rpc::DaemonSettings& rpcdaemon_settings,
    log::Level log_verbosity) {
    return chainsync::EngineRpcSettings{
        .engine_end_point = rpcdaemon_settings.engine_end_point,
        .engine_ifc_log_settings = rpcdaemon_settings.engine_ifc_log_settings,
        .private_api_addr = rpcdaemon_settings.private_api_addr,
        .log_verbosity = log_verbosity,
        .jwt_secret_file = rpcdaemon_settings.jwt_secret_file,
    };
}

static stagedsync::TimerFactory make_log_timer_factory(
    const boost::asio::any_io_executor& executor,
    uint32_t sync_loop_log_interval_seconds) {
    return [=](std::function<bool()> callback) {
        return std::make_shared<Timer>(
            executor,
            sync_loop_log_interval_seconds * 1'000,
            std::move(callback));
    };
}

static stagedsync::BodiesStageFactory make_bodies_stage_factory(
    const ChainConfig& chain_config,
    db::DataModelFactory data_model_factory,
    const NodeImpl& node) {
    return [&chain_config, data_model_factory = std::move(data_model_factory), &node](stagedsync::SyncContext* sync_context) {
        return std::make_unique<stagedsync::BodiesStage>(
            sync_context,
            chain_config,
            data_model_factory,
            [&node]() { return node.last_pre_validated_block(); });
    };
};

static stagedsync::StageContainerFactory make_stages_factory(
    const NodeSettings& node_settings,
    db::DataModelFactory data_model_factory,
    const NodeImpl& node) {
    auto bodies_stage_factory = make_bodies_stage_factory(*node_settings.chain_config, data_model_factory, node);
    return stagedsync::StagesFactoryImpl::to_factory({
        node_settings,
        std::move(data_model_factory),
        std::move(bodies_stage_factory),
    });
}

static sentry::SessionSentryClient::StatusDataProvider make_sentry_eth_status_data_provider(
    datastore::kvdb::ROAccess db_access,
    const ChainConfig& chain_config) {
    auto chain_head_provider = [db_access = std::move(db_access)] {
        return db::read_chain_head(db_access);
    };
    sentry::eth::StatusDataProvider provider{std::move(chain_head_provider), chain_config};
    return sentry::eth::StatusDataProvider::to_factory_function(std::move(provider));
}

NodeImpl::NodeImpl(
    rpc::ClientContextPool& context_pool,
    Settings& settings)
    : settings_{settings},
      data_store_{
          init_chain_data_db(settings.node_settings),
          settings_.snapshot_settings.repository_path,
      },
      execution_engine_{
          execution_ioc_.get_executor(),
          settings_.node_settings,
          data_model_factory(),
          make_log_timer_factory(context_pool.any_executor(), settings_.node_settings.sync_loop_log_interval_seconds),
          make_stages_factory(settings_.node_settings, data_model_factory(), *this),
          data_store_.chaindata().access_rw(),
      },
      execution_service_{std::make_shared<execution::api::ActiveDirectService>(execution_engine_, execution_ioc_)},
      execution_server_{make_execution_server_settings(settings_.node_settings.exec_api_address), execution_service_},
      execution_direct_client_{execution_service_},
      snapshot_sync_{
          settings.snapshot_settings,
          chain_config().chain_id,
          data_store(),
          settings_.node_settings.data_directory->temp().path(),
          execution_engine_.stage_scheduler(),
      },
      sentry_{
          sentry::SentryClientFactory::make_sentry(
              std::move(settings.sentry_settings),
              settings.node_settings.remote_sentry_addresses,
              context_pool.as_executor_pool(),
              context_pool,
              make_sentry_eth_status_data_provider(data_store_.chaindata().access_ro(), chain_config()))},
      chain_sync_{
          context_pool.any_executor(),
          data_store(),
          execution_direct_client_,
          std::get<0>(sentry_),
          chain_config(),
          /* use_preverified_hashes = */ true,
          make_sync_engine_rpc_settings(settings.rpcdaemon_settings, settings.log_settings.log_verbosity),
      },
      resource_usage_log_{*settings_.node_settings.data_directory} {
    backend_ = std::make_unique<EthereumBackEnd>(settings_.node_settings, data_store_.chaindata().access_ro(), std::get<0>(sentry_));
    backend_->set_node_name(settings_.node_settings.build_info.node_name);
    backend_kv_rpc_server_ = std::make_unique<BackEndKvServer>(settings_.server_settings, *backend_);
    bittorrent_client_ = std::make_unique<snapshots::bittorrent::BitTorrentClient>(settings_.snapshot_settings.bittorrent_settings);
}

Task<void> NodeImpl::wait_for_setup() {
    co_await snapshot_sync_.wait_for_setup();
}

Task<void> NodeImpl::run() {
    using namespace concurrency::awaitable_wait_for_all;

    try {
        co_await (
            run_tasks() &&
            snapshot_sync_.run() &&
            embedded_sentry_run_if_needed());
    } catch (const boost::system::system_error& ex) {
        SILK_ERROR_M("node") << "NodeImpl::run ex=" << ex.what();
        if (ex.code() == boost::system::errc::operation_canceled) {
            // TODO(canepat) demote to debug after https://github.com/erigontech/silkworm/issues/2333 is solved
            SILK_WARN_M("node") << "NodeImpl::run operation_canceled";
        }
        throw;
    }
}

Task<void> NodeImpl::run_tasks() {
    using namespace concurrency::awaitable_wait_for_all;

    co_await wait_for_setup();

    co_await (
        run_execution_service() &&
        run_execution_server() &&
        resource_usage_log_.run() &&
        run_chain_sync() &&
        run_backend_kv_grpc_server());
}

Task<void> NodeImpl::run_execution_service() {
    // Thread running block execution requires custom stack size because of deep EVM call stacks
    return execution_service_->async_run("exec-engine", /* stack_size = */ kExecutionThreadStackSize);
}

Task<void> NodeImpl::run_execution_server() {
    // Thread running block execution requires custom stack size because of deep EVM call stacks
    if (settings_.node_settings.exec_api_address) {
        co_await execution_server_.async_run(/* stack_size = */ kExecutionThreadStackSize);
    }
}

Task<void> NodeImpl::run_backend_kv_grpc_server() {
    auto run = [this]() {
        backend_kv_rpc_server_->build_and_start();
        backend_kv_rpc_server_->join();
    };
    auto stop = [this]() {
        backend_kv_rpc_server_->shutdown();
    };
    co_await concurrency::async_thread(std::move(run), std::move(stop), "bekv-server");
}

Task<void> NodeImpl::embedded_sentry_run_if_needed() {
    sentry::SentryClientFactory::SentryServerPtr server = std::get<1>(sentry_);
    if (server) {
        co_await server->run();
    }
}

Task<void> NodeImpl::run_chain_sync() {
    if (!settings_.node_settings.exec_api_address) {
        co_await chain_sync_.async_run();
    }
}

Node::Node(
    rpc::ClientContextPool& context_pool,
    Settings& settings)
    : p_impl_(std::make_unique<NodeImpl>(
          context_pool,
          settings)) {}

// Must be here (not in header) because NodeImpl size is necessary for std::unique_ptr in PIMPL idiom
Node::~Node() = default;

Task<void> Node::run() {
    return p_impl_->run();
}

Task<void> Node::wait_for_setup() {
    return p_impl_->wait_for_setup();
}

}  // namespace silkworm::node
