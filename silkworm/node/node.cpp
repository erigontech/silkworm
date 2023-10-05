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

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/os.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/node/backend/ethereum_backend.hpp>
#include <silkworm/node/backend/remote/backend_kv_server.hpp>
#include <silkworm/node/bittorrent/client.hpp>
#include <silkworm/node/common/preverified_hashes.hpp>
#include <silkworm/node/common/resource_usage.hpp>
#include <silkworm/node/snapshot/sync.hpp>
#include <silkworm/node/stagedsync/server.hpp>

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

    execution::LocalClient& execution_local_client() { return execution_local_client_; }
    std::shared_ptr<sentry::api::SentryClient> sentry_client() { return sentry_client_; }

    void setup();

    Task<void> run();

  private:
    void setup_snapshots();

    Task<void> run_tasks();
    Task<void> start_execution_server();
    Task<void> start_backend_kv_grpc_server();
    Task<void> start_bittorrent_client();
    Task<void> start_resource_usage_log();
    Task<void> start_execution_log_timer();

    Settings& settings_;
    mdbx::env chaindata_db_;

    //! The repository for snapshots
    snapshot::SnapshotRepository snapshot_repository_;

    //! The execution layer server engine
    execution::Server execution_server_;
    execution::LocalClient execution_local_client_;
    SentryClientPtr sentry_client_;
    std::unique_ptr<EthereumBackEnd> backend_;
    std::unique_ptr<rpc::BackEndKvServer> backend_kv_rpc_server_;
    ResourceUsageLog resource_usage_log_;
    std::unique_ptr<BitTorrentClient> bittorrent_client_;
};

NodeImpl::NodeImpl(Settings& settings, SentryClientPtr sentry_client, mdbx::env chaindata_db)
    : settings_{settings},
      chaindata_db_{chaindata_db},
      snapshot_repository_{settings_.snapshot_settings},
      execution_server_{settings_, db::RWAccess{chaindata_db_}},
      execution_local_client_{execution_server_},
      sentry_client_{std::move(sentry_client)},
      resource_usage_log_{settings_} {
    backend_ = std::make_unique<EthereumBackEnd>(settings_, &chaindata_db_, sentry_client_);
    backend_->set_node_name(settings_.node_name);
    backend_kv_rpc_server_ = std::make_unique<rpc::BackEndKvServer>(settings.server_settings, *backend_);
    bittorrent_client_ = std::make_unique<BitTorrentClient>(settings_.snapshot_settings.bittorrent_settings);
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
        snapshot::SnapshotSync snapshot_sync{&snapshot_repository_, settings_.chain_config.value()};
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
    return (run_tasks() && start_backend_kv_grpc_server() && start_bittorrent_client());
}

Task<void> NodeImpl::run_tasks() {
    using namespace concurrency::awaitable_wait_for_all;
    co_await (start_execution_server() && start_resource_usage_log() && start_execution_log_timer());
}

Task<void> NodeImpl::start_execution_server() {
    // Thread running block execution requires custom stack size because of deep EVM call stacks
    return execution_server_.async_run("exec-engine", /*stack_size=*/kExecutionThreadStackSize);
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
    : p_impl_(std::make_unique<NodeImpl>(settings, std::move(sentry_client), chaindata_db)) {}

// Must be here (not in header) because NodeImpl size is necessary for std::unique_ptr in PIMPL idiom
Node::~Node() = default;

execution::LocalClient& Node::execution_local_client() {
    return p_impl_->execution_local_client();
}

void Node::setup() {
    return p_impl_->setup();
}

Task<void> Node::run() {
    return p_impl_->run();
}

}  // namespace silkworm::node
