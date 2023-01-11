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

#include <silkworm/common/log.hpp>
#include <silkworm/lightclient/fork/fork.hpp>
#include <silkworm/lightclient/sentinel/sentinel_client.hpp>
#include <silkworm/lightclient/sentinel/sentinel_server.hpp>
#include <silkworm/lightclient/state/beacon-chain/beacon_state.hpp>
#include <silkworm/lightclient/state/checkpoint.hpp>
#include <silkworm/lightclient/state/storage.hpp>

#include <silkworm/lightclient/util/http_session.hpp>

namespace silkworm::cl {

using namespace boost::asio;

class LightClientImpl final {
  public:
    explicit LightClientImpl(Settings&& settings);

    void start();
    void stop();

    void join();

  private:
    void spawn_tasks();

    awaitable<void> run_tasks();

    awaitable<bool> bootstrap_checkpoint(const Hash32& finalized_root);

    Settings settings_;

    GenesisConfig genesis_config_;

    BeaconChainConfig beacon_config_;

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
      sentinel_client_{std::make_unique<sentinel::LocalClient>(sentinel_server_.get())},
      context_pool_{settings_.num_contexts} {
    for (std::size_t i{0}; i < settings_.num_contexts; ++i) {
        context_pool_.add_context(std::make_unique<DummyServerCompletionQueue>(), settings_.wait_mode);
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

    const std::string checkpoint_uri{"https://mainnet-checkpoint-sync.stakely.io/eth/v2/debug/beacon/states/finalized"};
    auto beacon_state = co_await retrieve_beacon_state(checkpoint_uri);

    auto root = beacon_state->finalized_checkpoint().root;
    Hash32 root_hash{};
    std::copy(root.cbegin(), root.cend(), root_hash.bytes);

    const bool result = co_await bootstrap_checkpoint(root_hash);
    log::Info() << "[LightClient] Bootstrap sequence completed [result=" << result << "]";

    const auto digest = compute_fork_digest(beacon_config_, genesis_config_);
    (void)digest;  // TODO(canepat) pass digest
    co_await (sentinel_server_->start() && sentinel_client_->start());
}

awaitable<bool> LightClientImpl::bootstrap_checkpoint(const Hash32& finalized_root) {
    log::Info() << "[Checkpoint Sync] Retrieving boostrap from sentinel [root: " << to_hex(finalized_root) << "]";

    int retries{0};
    std::shared_ptr<LightClientBootstrap> bootstrap;
    do {
        bootstrap = co_await sentinel_client_->bootstrap_request_v1(finalized_root);
        ++retries;
    } while (!bootstrap && retries <= 1);

    if (bootstrap) {  // TODO(canepat) after implementation remove retries and this check
        storage_ = std::make_unique<Storage>(finalized_root, *bootstrap);
        log::Info() << "[LightClient] Store initialized successfully [slot: " << storage_->finalized_header()->slot
                    << " root: " << to_hex(storage_->finalized_header()->root) << "]";
    }

    co_return true;
}

LightClient::LightClient(Settings settings)
    : p_impl_(std::make_unique<LightClientImpl>(std::move(settings))) {
}

LightClient::~LightClient() {
    log::Trace() << "silkworm::sentry::Sentry::~Sentry";
}

void LightClient::start() { p_impl_->start(); }

void LightClient::stop() { p_impl_->stop(); }

void LightClient::join() { p_impl_->join(); }

}  // namespace silkworm::cl
