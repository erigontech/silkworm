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

#include <cassert>
#include <functional>
#include <optional>
#include <string>

#include <boost/asio/ip/address.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/enode_url.hpp>

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
    explicit SentryImpl(Settings settings, silkworm::rpc::ServerContextPool& context_pool);

    SentryImpl(const SentryImpl&) = delete;
    SentryImpl& operator=(const SentryImpl&) = delete;

    Task<void> run();

    [[nodiscard]] std::shared_ptr<api::Service> service() { return direct_service_; }

  private:
    void setup_node_key();
    Task<void> run_tasks();
    Task<void> start_status_manager();
    Task<void> start_server();
    Task<void> start_discovery();
    Task<void> start_peer_manager();
    Task<void> start_message_sender();
    Task<void> start_message_receiver();
    Task<void> start_peer_manager_api();
    Task<void> run_peer_discovery_feedback();
    Task<void> start_grpc_server();
    std::unique_ptr<rlpx::Protocol> make_protocol();
    std::function<std::unique_ptr<rlpx::Protocol>()> protocol_factory();
    std::unique_ptr<rlpx::Client> make_client();
    std::function<std::unique_ptr<rlpx::Client>()> client_factory();
    [[nodiscard]] std::string client_id() const;
    [[nodiscard]] EnodeUrl make_node_url() const;
    [[nodiscard]] api::NodeInfo make_node_info() const;
    [[nodiscard]] std::function<api::NodeInfo()> node_info_provider() const;
    [[nodiscard]] std::function<EccKeyPair()> node_key_provider() const;
    [[nodiscard]] std::function<EnodeUrl()> node_url_provider() const;

    Settings settings_;
    std::optional<NodeKey> node_key_;
    std::optional<boost::asio::ip::address> public_ip_;
    silkworm::rpc::ServerContextPool& context_pool_;

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

SentryImpl::SentryImpl(Settings settings, silkworm::rpc::ServerContextPool& context_pool)
    : settings_(std::move(settings)),
      context_pool_(context_pool),
      status_manager_(context_pool_.next_io_context()),
      rlpx_server_(context_pool_.next_io_context(), settings_.port),
      discovery_(
          [this] { return boost::asio::any_io_executor(context_pool_.next_io_context().get_executor()); },
          settings_.static_peers,
          !settings_.no_discover,
          settings_.data_dir_path,
          node_key_provider(),
          node_url_provider(),
          settings_.port),
      peer_manager_(context_pool_.next_io_context(), settings_.max_peers, context_pool_),
      message_sender_(context_pool_.next_io_context()),
      message_receiver_(std::make_shared<MessageReceiver>(context_pool_.next_io_context(), settings_.max_peers)),
      peer_manager_api_(std::make_shared<PeerManagerApi>(context_pool_.next_io_context(), peer_manager_)),
      peer_discovery_feedback_(std::make_shared<PeerDiscoveryFeedback>(boost::asio::any_io_executor(context_pool_.next_io_context().get_executor()), settings_.max_peers)),
      service_router_(make_service_router(status_manager_.status_channel(), message_sender_, *message_receiver_, *peer_manager_api_, node_info_provider())),
      direct_service_(std::make_shared<api::router::DirectService>(service_router_)),
      grpc_server_(make_server_config(settings_), service_router_) {
}

Task<void> SentryImpl::run() {
    using namespace concurrency::awaitable_wait_for_all;

    setup_node_key();

    public_ip_ = co_await nat::ip_resolver(settings_.nat);
    log::Info("sentry") << "Node URL: " << make_node_url().to_string();

    co_await (run_tasks() && start_grpc_server());
}

void SentryImpl::setup_node_key() {
    DataDirectory data_dir{settings_.data_dir_path, true};
    NodeKey node_key = node_key_get_or_generate(settings_.node_key, data_dir);
    node_key_ = {node_key};
}

Task<void> SentryImpl::run_tasks() {
    using namespace concurrency::awaitable_wait_for_all;

    log::Info("sentry") << "Sentry is waiting for status message...";
    co_await status_manager_.wait_for_status();
    log::Info("sentry") << "Sentry received initial status message";

    co_await (
        start_status_manager() &&
        start_server() &&
        start_discovery() &&
        start_peer_manager() &&
        start_message_sender() &&
        start_message_receiver() &&
        start_peer_manager_api() &&
        run_peer_discovery_feedback());
}

std::unique_ptr<rlpx::Protocol> SentryImpl::make_protocol() {
    return std::unique_ptr<rlpx::Protocol>(new eth::Protocol(status_manager_.status_provider()));
}

std::function<std::unique_ptr<rlpx::Protocol>()> SentryImpl::protocol_factory() {
    return [this] { return this->make_protocol(); };
}

Task<void> SentryImpl::start_status_manager() {
    return status_manager_.start();
}

Task<void> SentryImpl::start_server() {
    return rlpx_server_.start(context_pool_, node_key_.value(), client_id(), protocol_factory());
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

Task<void> SentryImpl::start_discovery() {
    return discovery_.run();
}

Task<void> SentryImpl::start_peer_manager() {
    return peer_manager_.start(rlpx_server_, discovery_, client_factory());
}

Task<void> SentryImpl::start_message_sender() {
    return message_sender_.start(peer_manager_);
}

Task<void> SentryImpl::start_message_receiver() {
    return MessageReceiver::start(message_receiver_, peer_manager_);
}

Task<void> SentryImpl::start_peer_manager_api() {
    return PeerManagerApi::start(peer_manager_api_);
}

Task<void> SentryImpl::run_peer_discovery_feedback() {
    return PeerDiscoveryFeedback::run(peer_discovery_feedback_, peer_manager_, discovery_);
}

Task<void> SentryImpl::start_grpc_server() {
    if (!settings_.api_address.empty()) {
        co_await grpc_server_.async_run();
    }
}

static std::string make_client_id(const buildinfo& info) {
    return std::string(info.project_name) +
           "/v" + info.project_version +
           "/" + info.system_name + "-" + info.system_processor +
           "/" + info.compiler_id + "-" + info.compiler_version;
}

std::string SentryImpl::client_id() const {
    if (settings_.build_info)
        return make_client_id(*settings_.build_info);
    return "silkworm";
}

EnodeUrl SentryImpl::make_node_url() const {
    assert(node_key_);
    assert(public_ip_);
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

std::function<api::NodeInfo()> SentryImpl::node_info_provider() const {
    return [this] { return this->make_node_info(); };
}

std::function<EccKeyPair()> SentryImpl::node_key_provider() const {
    return [this] {
        assert(this->node_key_);
        return this->node_key_.value();
    };
}

std::function<EnodeUrl()> SentryImpl::node_url_provider() const {
    return [this] { return this->make_node_url(); };
}

Sentry::Sentry(Settings settings, silkworm::rpc::ServerContextPool& context_pool)
    : p_impl_(std::make_unique<SentryImpl>(std::move(settings), context_pool)) {
}

Sentry::~Sentry() {
    log::Trace("sentry") << "silkworm::sentry::Sentry::~Sentry";
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
