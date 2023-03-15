/*
   Copyright 2022 The Silkworm Authors

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

#include "light_client.hpp"

#include <future>
#include <memory>
#include <set>
#include <stdexcept>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/signal_set.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/lightclient/fork/fork.hpp>
#include <silkworm/lightclient/params/config.hpp>
#include <silkworm/lightclient/sentinel/sentinel_client.hpp>
#include <silkworm/lightclient/sentinel/sentinel_server.hpp>
#include <silkworm/lightclient/sentinel/remote_client.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/beacon_state.hpp>
#include <silkworm/lightclient/ssz/constants.hpp>
#include <silkworm/lightclient/state/checkpoint.hpp>
#include <silkworm/lightclient/state/storage.hpp>
#include <silkworm/node/common/log.hpp>
#include <silkworm/sentry/common/timeout.hpp>

namespace silkworm::cl {

using namespace boost::asio;
using namespace std::chrono_literals;

constexpr auto kSetStatusRetryInterval{10s};

class LightClientImpl final {
  public:
    explicit LightClientImpl(Settings&& settings);

    void start();
    void stop();

    void join();

  private:
    void spawn_tasks();

    awaitable<void> run_tasks();

    awaitable<bool> bootstrap_checkpoint(const eth::Root& finalized_root);

    awaitable<void> set_sentinel_status(const eth::Checkpoint& finalized);
    awaitable<void> update_sentinel_status();

    Settings settings_;

    ConsensusConfig config_;

    //! The highest Execution chain (aka ETH1) block seen by this LC
    // BlockNum highest_eth1_block_seen_{0};

    //! The highest Beacon chain (aka ETH2) slot validated by this LC
    // uint64_t highest_eth2_slot_validated_{0};

    //! The highest execution block seen by this LC
    // evmc::bytes32 highest_processed_root_;

    //! The last Beacon chain parent root hash
    // evmc::bytes32 last_eth2_parent_root_;

    //! The cache containing hashes of recently added beacon blocks
    std::set<evmc::bytes32> recent_hashes_;

    // kv.RwDB db_;

    std::unique_ptr<sentinel::Server> sentinel_server_;
    std::unique_ptr<sentinel::Client> sentinel_client_;

    std::promise<void> stop_tasks_;
    boost::asio::cancellation_signal stop_signal_;

    rpc::ServerContextPool context_pool_;
    std::unique_ptr<boost::asio::signal_set> shutdown_signals_;

    std::unique_ptr<Storage> storage_;
};

static void rethrow_unless_cancelled(const std::exception_ptr& ex_ptr) {
    if (!ex_ptr) return;
    try {
        std::rethrow_exception(ex_ptr);
    } catch (const boost::system::system_error& e) {
        if (e.code() != boost::system::errc::operation_canceled) throw;
    }
}

class DummyServerCompletionQueue : public grpc::ServerCompletionQueue {
};

LightClientImpl::LightClientImpl(Settings&& settings)
    : settings_(std::move(settings)),
      sentinel_server_{std::make_unique<sentinel::Server>()},
      context_pool_{settings_.num_contexts} {
    for (std::size_t i{0}; i < settings_.num_contexts; ++i) {
        context_pool_.add_context(std::make_unique<DummyServerCompletionQueue>(), settings_.wait_mode);
    }

    const auto& sentinel_address = settings_.sentinel_address;
    if (sentinel_address.empty()) {
        sentinel_client_ = std::make_unique<sentinel::LocalClient>(sentinel_server_.get());
    } else {
        auto channel = grpc::CreateChannel(sentinel_address, grpc::InsecureChannelCredentials());
        sentinel_client_ = std::make_unique<sentinel::RemoteClient>(*context_pool_.next_context().client_grpc_context(), channel);
    }
}

void LightClientImpl::start() {
    shutdown_signals_ = std::make_unique<signal_set>(context_pool_.next_io_context(), SIGINT, SIGTERM);
    shutdown_signals_->async_wait([&](const boost::system::error_code& error, int signal_number) {
        std::cout << "\n";
        log::Info() << "[LightClient] Signal caught, error: " << error << " number: " << signal_number;
        this->stop();
    });

    spawn_tasks();

    context_pool_.start();
}

void LightClientImpl::stop() {
    stop_signal_.emit(cancellation_type::all);
}

void LightClientImpl::join() {
    stop_tasks_.get_future().wait();

    context_pool_.stop();
    context_pool_.join();
}

void LightClientImpl::spawn_tasks() {
    auto tasks_completion = [&](const std::exception_ptr& ex_ptr) {
        rethrow_unless_cancelled(ex_ptr);
        log::Info() << "Handle tasks cancellation";
        this->stop_tasks_.set_value();
    };
    co_spawn(
        context_pool_.next_io_context(),
        this->run_tasks(),
        bind_cancellation_slot(stop_signal_.slot(), tasks_completion));
}

awaitable<void> LightClientImpl::run_tasks() {
    using namespace boost::asio::experimental::awaitable_operators;

    log::Info() << "[LightClient] Waiting for bootstrap sequence...";

    const auto consensus_config = lookup_consensus_config(settings_.chain_id);
    if (!consensus_config) {
        log::Critical() << "[Checkpoint Sync] Cannot lookup consensus config [chain_id: " << settings_.chain_id << "]";
        co_return;
    }
    config_ = *consensus_config;

    auto checkpoint_uri = get_checkpoint_sync_endpoint(settings_.chain_id);
    SILKWORM_ASSERT(checkpoint_uri);
    if (!checkpoint_uri) {
        log::Critical() << "[Checkpoint Sync] Cannot lookup checkpoint sync ep [chain_id: " << settings_.chain_id << "]";
        co_return;
    }

    constexpr auto kRetryInterval{5s};
    sentry::common::Timeout timeout{kRetryInterval, /*no_throw*/true};
    std::unique_ptr<eth::BeaconState> beacon_state;
    do {
        log::Info() << "[Checkpoint Sync] Requesting beacon state [uri: " << *checkpoint_uri << "]";
        beacon_state = co_await retrieve_beacon_state(*checkpoint_uri);
        if (!beacon_state) co_await timeout();
    } while (!beacon_state);

    const auto finalized_root = beacon_state->finalized_checkpoint().root;
    log::Info() << "[Checkpoint Sync] Beacon state retrieved [root: " << to_hex(finalized_root.to_array()) << "]";

    co_await set_sentinel_status(beacon_state->finalized_checkpoint());
    log::Info() << "[Checkpoint Sync] Status set for sentinel [root: " << to_hex(finalized_root.to_array()) << "]";

    const bool result = co_await bootstrap_checkpoint(finalized_root);
    log::Info() << "[LightClient] Bootstrap sequence completed [result=" << result << "]";

    co_await (sentinel_server_->start() && sentinel_client_->start() && update_sentinel_status());
}

awaitable<bool> LightClientImpl::bootstrap_checkpoint(const eth::Root& finalized_root) {
    log::Info() << "[Checkpoint Sync] Retrieving boostrap from sentinel [root: " << to_hex({finalized_root.to_array()}) << "]";

    constexpr auto kRetryInterval{5s};
    sentry::common::Timeout timeout{kRetryInterval, /*no_throw*/true};
    std::shared_ptr<eth::LightClientBootstrap> bootstrap;
    do {
        bootstrap = co_await sentinel_client_->bootstrap_request_v1(finalized_root); // TODO(canepat) || timeout(30s)
        if (!bootstrap) co_await timeout();  // TODO(canepat) in case NOT timeout: co_await sleep(5s);
    } while (!bootstrap);
    log::Info() << "[Checkpoint Sync] Boostrap retrieved [header_root: " << to_hex(bootstrap->header().hash_tree_root()) << "]";

    storage_ = std::make_unique<Storage>(finalized_root, *bootstrap);
    log::Info() << "[LightClient] Store initialized successfully [slot: " << storage_->finalized_header().slot
                << " root: " << to_hex(storage_->finalized_header().state_root.to_array()) << "]";

    co_return true;
}

awaitable<void> LightClientImpl::set_sentinel_status(const eth::Checkpoint& finalized) {
    sentry::common::Timeout timeout{kSetStatusRetryInterval, /*no_throw*/true};
    while (true) {
        try {
            const auto digest = compute_fork_digest(config_.beacon_chain_config, config_.genesis_config);
            log::Info() << "[Checkpoint Sync] Computed fork digest [data: " << to_hex(digest) << "]";
            const auto& finalized_root = finalized.hash_tree_root();
            cl::sentinel::Status status{
                .fork_digest = endian::load_big_u32(digest.data()),
                .finalized_root = to_bytes32({finalized_root.data(), finalized_root.size()}),
                .finalized_epoch = finalized.epoch,
                .head_root = to_bytes32({finalized_root.data(), finalized_root.size()}),
                .head_slot = finalized.epoch * constants::kSlotsPerEpoch,
            };
            co_await sentinel_client_->set_status(status);
            break;
        } catch (const std::exception& ex) {
            log::Error() << "[Checkpoint Sync] Cannot set status for sentinel [" << ex.what() << "]";
        }
        co_await timeout();  // TODO(canepat) replace with sleep
    };
}

awaitable<void> LightClientImpl::update_sentinel_status() {
    sentry::common::Timeout timeout{kSetStatusRetryInterval, /*no_throw*/true};
    while (true) {
        const eth::BeaconBlockHeader& finalized_header = storage_->finalized_header();
        const eth::BeaconBlockHeader& optimistic_header = storage_->optimistic_header();
        const auto digest = compute_fork_digest(config_.beacon_chain_config, config_.genesis_config);
        const auto& finalized_root = finalized_header.hash_tree_root();
        const auto& head_root = optimistic_header.hash_tree_root();
        cl::sentinel::Status status{
            .fork_digest = endian::load_big_u32(digest.data()),
            .finalized_root = to_bytes32({finalized_root.data(), finalized_root.size()}),
            .finalized_epoch = finalized_header.slot / constants::kSlotsPerEpoch,
            .head_root = to_bytes32({head_root.data(), head_root.size()}),
            .head_slot = optimistic_header.slot,
        };
        co_await sentinel_client_->set_status(status);
        co_await timeout();  // TODO(canepat) replace with sleep
    }
}

LightClient::LightClient(Settings settings)
    : p_impl_(std::make_unique<LightClientImpl>(std::move(settings))) {
}

LightClient::~LightClient() = default;

void LightClient::start() { p_impl_->start(); }

void LightClient::stop() { p_impl_->stop(); }

void LightClient::join() { p_impl_->join(); }

}  // namespace silkworm::cl
