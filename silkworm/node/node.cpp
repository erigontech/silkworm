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

#include <silkworm/db/freezer.hpp>
#include <silkworm/db/snapshot_bundle_factory_impl.hpp>
#include <silkworm/db/snapshot_sync.hpp>
#include <silkworm/db/snapshots/bittorrent/client.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/os.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/node/backend/ethereum_backend.hpp>
#include <silkworm/node/common/preverified_hashes.hpp>
#include <silkworm/node/execution/api/active_direct_service.hpp>
#include <silkworm/node/execution/grpc/server/server.hpp>
#include <silkworm/node/resource_usage.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>

#include "backend_kv_server.hpp"

namespace silkworm::node {

constexpr uint64_t kMaxFileDescriptors{10'240};

//! Custom stack size for thread running block execution on EVM
constexpr uint64_t kExecutionThreadStackSize{16'777'216};  // 16MiB

using SentryClientPtr = std::shared_ptr<sentry::api::SentryClient>;

class NodeImpl final {
  public:
    NodeImpl(Settings& settings, SentryClientPtr sentry_client, mdbx::env chaindata_db);

    NodeImpl(const NodeImpl&) = delete;
    NodeImpl& operator=(const NodeImpl&) = delete;

    execution::api::DirectClient& execution_direct_client() { return execution_direct_client_; }
    std::shared_ptr<sentry::api::SentryClient> sentry_client() { return sentry_client_; }

    void setup();

    Task<void> run();

  private:
    void setup_snapshots();

    Task<void> start_execution_server();
    Task<void> start_backend_kv_grpc_server();
    Task<void> start_bittorrent_client();
    Task<void> start_resource_usage_log();
    Task<void> start_execution_log_timer();

    Settings& settings_;

    mdbx::env chaindata_db_;

    //! The repository for snapshots
    snapshots::SnapshotRepository snapshot_repository_;

    //! The execution layer server engine
    boost::asio::io_context execution_context_;
    stagedsync::ExecutionEngine execution_engine_;
    std::shared_ptr<execution::api::ActiveDirectService> execution_service_;
    execution::grpc::server::Server execution_server_;
    execution::api::DirectClient execution_direct_client_;

    db::Freezer snapshot_freezer_;

    SentryClientPtr sentry_client_;

    std::unique_ptr<EthereumBackEnd> backend_;
    std::unique_ptr<BackEndKvServer> backend_kv_rpc_server_;

    ResourceUsageLog resource_usage_log_;

    std::unique_ptr<snapshots::bittorrent::BitTorrentClient> bittorrent_client_;
};

static auto make_execution_server_settings() {
    return rpc::ServerSettings{
        .address_uri = "localhost:9092",
        .context_pool_settings = {.num_contexts = 1},  // just one execution context
    };
}

NodeImpl::NodeImpl(Settings& settings, SentryClientPtr sentry_client, mdbx::env chaindata_db)
    : settings_{settings},
      chaindata_db_{std::move(chaindata_db)},
      snapshot_repository_{settings_.snapshot_settings, std::make_unique<db::SnapshotBundleFactoryImpl>()},
      execution_engine_{execution_context_, settings_, db::RWAccess{chaindata_db_}},
      execution_service_{std::make_shared<execution::api::ActiveDirectService>(execution_engine_, execution_context_)},
      execution_server_{make_execution_server_settings(), execution_service_},
      execution_direct_client_{execution_service_},
      snapshot_freezer_{db::ROAccess{chaindata_db_}, snapshot_repository_, execution_engine_.stage_scheduler(), settings_.data_directory->temp().path()},
      sentry_client_{std::move(sentry_client)},
      resource_usage_log_{*settings_.data_directory} {
    backend_ = std::make_unique<EthereumBackEnd>(settings_, &chaindata_db_, sentry_client_);
    backend_->set_node_name(settings_.build_info.node_name);
    backend_kv_rpc_server_ = std::make_unique<BackEndKvServer>(settings_.server_settings, *backend_);
    bittorrent_client_ = std::make_unique<snapshots::bittorrent::BitTorrentClient>(settings_.snapshot_settings.bittorrent_settings);
}

void NodeImpl::setup() {
    PreverifiedHashes::load(settings_.chain_config->chain_id);

    setup_snapshots();
}

void NodeImpl::setup_snapshots() {
    if (settings_.snapshot_settings.enabled) {
        // Raise file descriptor limit per process
        const bool set_fd_result = os::set_max_file_descriptors(kMaxFileDescriptors);
        if (!set_fd_result) {
            throw std::runtime_error{"Cannot increase max file descriptor up to " + std::to_string(kMaxFileDescriptors)};
        }

        db::RWTxnManaged rw_txn{chaindata_db_};

        // Snapshot sync - download chain from peers using snapshot files
        db::SnapshotSync snapshot_sync{&snapshot_repository_, settings_.chain_config.value()};
        snapshot_sync.download_and_index_snapshots(rw_txn);

        rw_txn.commit_and_stop();

        // Set snapshot repository into snapshot-aware database access
        db::DataModel::set_snapshot_repository(&snapshot_repository_);
    } else {
        log::Info() << "Snapshot sync disabled, no snapshot must be downloaded";
    }
}

Task<void> NodeImpl::run() {
    using namespace concurrency::awaitable_wait_for_all;
    co_await (
        start_execution_server() &&
        start_resource_usage_log() &&
        start_execution_log_timer() &&
        snapshot_freezer_.run_loop() &&
        start_backend_kv_grpc_server() &&
        start_bittorrent_client());
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

Task<void> NodeImpl::start_bittorrent_client() {
    if (settings_.snapshot_settings.bittorrent_settings.seeding) {
        auto run = [this]() {
            bittorrent_client_->execute_loop();
        };
        auto stop = [this]() {
            bittorrent_client_->stop();
        };
        co_await concurrency::async_thread(std::move(run), std::move(stop), "bit-torrent");
    }
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

Node::Node(Settings& settings, SentryClientPtr sentry_client, mdbx::env chaindata_db)
    : p_impl_(std::make_unique<NodeImpl>(settings, std::move(sentry_client), std::move(chaindata_db))) {}

// Must be here (not in header) because NodeImpl size is necessary for std::unique_ptr in PIMPL idiom
Node::~Node() = default;

execution::api::DirectClient& Node::execution_direct_client() {
    return p_impl_->execution_direct_client();
}

void Node::setup() {
    p_impl_->setup();
}

Task<void> Node::run() {
    return p_impl_->run();
}

}  // namespace silkworm::node
