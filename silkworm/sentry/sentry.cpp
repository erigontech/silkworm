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

#include "sentry.hpp"

#include <optional>
#include <string>

#include <boost/asio/ip/address.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/core/common/assert.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/enode_url.hpp>
#include <silkworm/sentry/discovery/common/node_address.hpp>
#include <silkworm/sentry/discovery/enr/enr_record.hpp>

#include "api/common/node_info.hpp"
#include "api/common/service.hpp"
#include "api/router/direct_service.hpp"
#include "api/router/service_router.hpp"
#include "discovery/discovery.hpp"
#include "eth/protocol.hpp"
#include "grpc/server/server.hpp"
#include "message_receiver.hpp"
#include "message_sender.hpp"
#include "nat/ip_resolver.hpp"
#include "node_key_config.hpp"
#include "peer_discovery_feedback.hpp"
#include "peer_manager.hpp"
#include "peer_manager_api.hpp"
#include "rlpx/client.hpp"
#include "rlpx/protocol.hpp"
#include "rlpx/server.hpp"
#include "status_manager.hpp"

namespace silkworm::sentry {

using namespace boost;

class SentryImpl final {
  public:
    explicit SentryImpl(Settings settings, concurrency::ExecutorPool& executor_pool);

    SentryImpl(const SentryImpl&) = delete;
    SentryImpl& operator=(const SentryImpl&) = delete;

    Task<void> run();

    std::shared_ptr<api::Service> service() { return direct_service_; }

  private:
    void setup_node_key();
    Task<void> run_tasks();
    Task<void> run_status_manager();
    Task<void> run_server();
    Task<void> run_discovery();
    Task<void> run_peer_manager();
    Task<void> run_message_sender();
    Task<void> run_message_receiver();
    Task<void> run_peer_manager_api();
    Task<void> run_peer_discovery_feedback();
    Task<void> run_grpc_server();
    std::unique_ptr<rlpx::Protocol> make_protocol();
    std::function<std::unique_ptr<rlpx::Protocol>()> protocol_factory();
    std::unique_ptr<rlpx::Client> make_client();
    std::function<std::unique_ptr<rlpx::Client>()> client_factory();
    std::string client_id() const;
    EnodeUrl make_node_url() const;
    api::NodeInfo make_node_info() const;
    discovery::enr::EnrRecord make_node_record();
    std::function<api::NodeInfo()> node_info_provider() const;
    std::function<EccKeyPair()> node_key_provider() const;
    std::function<EnodeUrl()> node_url_provider() const;
    std::function<discovery::enr::EnrRecord()> node_record_provider();

    Settings settings_;
    std::optional<NodeKey> node_key_;
    std::optional<boost::asio::ip::address> public_ip_;
    concurrency::ExecutorPool& executor_pool_;

    StatusManager status_manager_;

    rlpx::Server rlpx_server_;
    discovery::Discovery discovery_;
    PeerManager peer_manager_;

    MessageSender message_sender_;
    std::shared_ptr<MessageReceiver> message_receiver_;
    std::shared_ptr<PeerManagerApi> peer_manager_api_;
    std::shared_ptr<PeerDiscoveryFeedback> peer_discovery_feedback_;

    api::router::ServiceRouter service_router_;
    std::shared_ptr<api::router::DirectService> direct_service_;
    grpc::server::Server grpc_server_;
};

static silkworm::rpc::ServerSettings make_server_config(const Settings& settings) {
    silkworm::rpc::ServerSettings config{
        .address_uri = settings.api_address,
        .context_pool_settings = settings.context_pool_settings,
    };
    return config;
}

static api::router::ServiceRouter make_service_router(
    concurrency::Channel<eth::StatusData>& status_channel,
    MessageSender& message_sender,
    MessageReceiver& message_receiver,
    PeerManagerApi& peer_manager_api,
    std::function<api::NodeInfo()> node_info_provider) {
    return api::router::ServiceRouter{
        eth::Protocol::kVersion,
        status_channel,
        message_sender.send_message_channel(),
        message_receiver.message_calls_channel(),
        peer_manager_api.peer_count_calls_channel(),
        peer_manager_api.peers_calls_channel(),
        peer_manager_api.peer_calls_channel(),
        peer_manager_api.peer_penalize_calls_channel(),
        peer_manager_api.peer_events_calls_channel(),
        std::move(node_info_provider),
    };
}

SentryImpl::SentryImpl(Settings settings, concurrency::ExecutorPool& executor_pool)
    : settings_(std::move(settings)),
      executor_pool_(executor_pool),
      status_manager_(executor_pool.any_executor()),
      rlpx_server_(executor_pool.any_executor(), settings_.port),
      discovery_(
          executor_pool,
          settings_.static_peers,
          !settings_.no_discover,
          settings_.data_dir_path,
          settings_.network_id,
          node_key_provider(),
          node_url_provider(),
          node_record_provider(),
          settings_.bootnodes,
          settings_.port),
      peer_manager_(executor_pool.any_executor(), settings_.max_peers, executor_pool_),
      message_sender_(executor_pool.any_executor()),
      message_receiver_(std::make_shared<MessageReceiver>(executor_pool.any_executor(), settings_.max_peers)),
      peer_manager_api_(std::make_shared<PeerManagerApi>(executor_pool.any_executor(), peer_manager_)),
      peer_discovery_feedback_(std::make_shared<PeerDiscoveryFeedback>(executor_pool.any_executor(), settings_.max_peers)),
      service_router_(make_service_router(status_manager_.status_channel(), message_sender_, *message_receiver_, *peer_manager_api_, node_info_provider())),
      direct_service_(std::make_shared<api::router::DirectService>(service_router_)),
      grpc_server_(make_server_config(settings_), service_router_) {
}

Task<void> SentryImpl::run() {
    using namespace concurrency::awaitable_wait_for_all;

    setup_node_key();

    public_ip_ = co_await nat::ip_resolver(settings_.nat);
    SILK_INFO_M("sentry") << "Node URL: " << make_node_url().to_string();

    try {
        co_await (run_tasks() && run_grpc_server());
    } catch (const boost::system::system_error& ex) {
        SILK_ERROR_M("sentry") << "SentryImpl::run ex=" << ex.what();
        if (ex.code() == boost::system::errc::operation_canceled) {
            // TODO(canepat) demote to debug after https://github.com/erigontech/silkworm/issues/2333 is solved
            SILK_WARN_M("sentry") << "SentryImpl::run operation_canceled";
        }
        throw;
    }
}

void SentryImpl::setup_node_key() {
    DataDirectory data_dir{settings_.data_dir_path, true};
    NodeKey node_key = node_key_get_or_generate(settings_.node_key, data_dir);
    node_key_ = {node_key};
}

Task<void> SentryImpl::run_tasks() {
    using namespace concurrency::awaitable_wait_for_all;

    SILK_INFO_M("sentry") << "Sentry is waiting for status message...";
    co_await status_manager_.wait_for_status();
    SILK_INFO_M("sentry") << "Sentry received initial status message";

    try {
        co_await (
            run_status_manager() &&
            run_server() &&
            run_discovery() &&
            run_peer_manager() &&
            run_message_sender() &&
            run_message_receiver() &&
            run_peer_manager_api() &&
            run_peer_discovery_feedback());
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::system::errc::operation_canceled) {
            SILK_DEBUG_M("sentry") << "Sentry run_tasks unexpected end [operation_canceled]";
        } else {
            SILK_CRIT_M("sentry") << "Sentry run_tasks unexpected end [" + std::string{se.what()} + "]";
        }
        throw se;
    }
}

std::unique_ptr<rlpx::Protocol> SentryImpl::make_protocol() {
    return std::make_unique<eth::Protocol>(status_manager_.status_provider());
}

std::function<std::unique_ptr<rlpx::Protocol>()> SentryImpl::protocol_factory() {
    return [this] { return this->make_protocol(); };
}

Task<void> SentryImpl::run_status_manager() {
    return status_manager_.run();
}

Task<void> SentryImpl::run_server() {
    return rlpx_server_.run(executor_pool_, node_key_.value(), client_id(), protocol_factory());
}

std::unique_ptr<rlpx::Client> SentryImpl::make_client() {
    return std::make_unique<rlpx::Client>(
        node_key_.value(),
        client_id(),
        settings_.port,
        /* max_retries = */ 2,
        protocol_factory());
}

std::function<std::unique_ptr<rlpx::Client>()> SentryImpl::client_factory() {
    return [this] { return this->make_client(); };
}

Task<void> SentryImpl::run_discovery() {
    return discovery_.run();
}

Task<void> SentryImpl::run_peer_manager() {
    try {
        return peer_manager_.run(rlpx_server_, discovery_, make_protocol(), client_factory());
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::system::errc::operation_canceled) {
            SILK_DEBUG_M("sentry") << "run_peer_manager unexpected end [operation_canceled]";
        } else {
            SILK_CRIT_M("sentry") << "run_peer_manager unexpected end [" + std::string{se.what()} + "]";
        }
        throw se;
    }
}

Task<void> SentryImpl::run_message_sender() {
    try {
        return message_sender_.run(peer_manager_);
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::system::errc::operation_canceled) {
            SILK_DEBUG_M("sentry") << "run_message_sender unexpected end [operation_canceled]";
        } else {
            SILK_CRIT_M("sentry") << "run_message_sender unexpected end [" + std::string{se.what()} + "]";
        }
        throw se;
    }
}

Task<void> SentryImpl::run_message_receiver() {
    try {
        return MessageReceiver::run(message_receiver_, peer_manager_);
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::system::errc::operation_canceled) {
            SILK_DEBUG_M("sentry") << "run_message_receiver unexpected end [operation_canceled]";
        } else {
            SILK_CRIT_M("sentry") << "run_message_receiver unexpected end [" + std::string{se.what()} + "]";
        }
        throw se;
    }
}

Task<void> SentryImpl::run_peer_manager_api() {
    try {
        return PeerManagerApi::run(peer_manager_api_);
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::system::errc::operation_canceled) {
            SILK_DEBUG_M("sentry") << "run_peer_manager_api unexpected end [operation_canceled]";
        } else {
            SILK_CRIT_M("sentry") << "run_peer_manager_api unexpected end [" + std::string{se.what()} + "]";
        }
        throw se;
    }
}

Task<void> SentryImpl::run_peer_discovery_feedback() {
    try {
        return PeerDiscoveryFeedback::run(peer_discovery_feedback_, peer_manager_, discovery_);
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::system::errc::operation_canceled) {
            SILK_DEBUG_M("sentry") << "run_peer_discovery_feedback unexpected end [operation_canceled]";
        } else {
            SILK_CRIT_M("sentry") << "run_peer_discovery_feedback unexpected end [" + std::string{se.what()} + "]";
        }
        throw se;
    }
}

Task<void> SentryImpl::run_grpc_server() {
    if (!settings_.api_address.empty()) {
        co_await grpc_server_.async_run();
    }
}

std::string SentryImpl::client_id() const {
    return settings_.client_id;
}

EnodeUrl SentryImpl::make_node_url() const {
    SILKWORM_ASSERT(node_key_);
    SILKWORM_ASSERT(public_ip_);
    return EnodeUrl{
        node_key_.value().public_key(),
        public_ip_.value(),
        settings_.port,
        settings_.port,
    };
}

api::NodeInfo SentryImpl::make_node_info() const {
    return {
        make_node_url(),
        client_id(),
        rlpx_server_.listen_endpoint(),
        settings_.port,
    };
}

discovery::enr::EnrRecord SentryImpl::make_node_record() {
    discovery::NodeAddress address{*public_ip_, settings_.port, settings_.port};
    std::optional<discovery::NodeAddress> address_v4;
    std::optional<discovery::NodeAddress> address_v6;
    if (public_ip_->is_v4()) {
        address_v4 = std::move(address);
    } else if (public_ip_->is_v6()) {
        address_v6 = std::move(address);
    }

    auto status_data = status_manager_.status_provider()();
    Bytes eth1_fork_id_data = status_data.message.fork_id.rlp_encode_enr_entry();

    return {
        node_key_->public_key(),
        1,
        std::move(address_v4),
        std::move(address_v6),
        std::move(eth1_fork_id_data),
        std::nullopt,
        std::nullopt,
    };
}

std::function<api::NodeInfo()> SentryImpl::node_info_provider() const {
    return [this] { return this->make_node_info(); };
}

std::function<EccKeyPair()> SentryImpl::node_key_provider() const {
    return [this] {
        SILKWORM_ASSERT(this->node_key_);
        return this->node_key_.value();
    };
}

std::function<EnodeUrl()> SentryImpl::node_url_provider() const {
    return [this] { return this->make_node_url(); };
}

std::function<discovery::enr::EnrRecord()> SentryImpl::node_record_provider() {
    return [this] { return this->make_node_record(); };
}

Sentry::Sentry(Settings settings, concurrency::ExecutorPool& executor_pool)
    : p_impl_(std::make_unique<SentryImpl>(std::move(settings), executor_pool)) {
}

Sentry::~Sentry() {
    SILK_TRACE_M("sentry") << "silkworm::sentry::Sentry::~Sentry";
}

Task<void> Sentry::run() {
    return p_impl_->run();
}

Task<std::shared_ptr<api::Service>> Sentry::service() {
    co_return p_impl_->service();
}

bool Sentry::is_ready() {
    // the direct client never disconnects
    return true;
}

void Sentry::on_disconnect(std::function<Task<void>()> /*callback*/) {
    // the direct client never disconnects
}

Task<void> Sentry::reconnect() {
    // the direct client never disconnects
    co_return;
}

}  // namespace silkworm::sentry
