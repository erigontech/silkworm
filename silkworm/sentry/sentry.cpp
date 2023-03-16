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

#include <functional>
#include <optional>
#include <string>

#include <silkworm/buildinfo.h>
#include <silkworm/node/common/directories.hpp>
#include <silkworm/node/common/log.hpp>
#include <silkworm/sentry/common/awaitable_wait_for_all.hpp>
#include <silkworm/sentry/common/enode_url.hpp>

#include "api/api_common/node_info.hpp"
#include "discovery/discovery.hpp"
#include "eth/protocol.hpp"
#include "message_receiver.hpp"
#include "message_sender.hpp"
#include "node_key_config.hpp"
#include "peer_manager.hpp"
#include "peer_manager_api.hpp"
#include "rlpx/client.hpp"
#include "rlpx/protocol.hpp"
#include "rlpx/server.hpp"
#include "rpc/server/server.hpp"
#include "status_manager.hpp"

namespace silkworm::sentry {

using namespace boost;

class SentryImpl final {
  public:
    explicit SentryImpl(Settings settings, silkworm::rpc::ServerContextPool& context_pool);

    SentryImpl(const SentryImpl&) = delete;
    SentryImpl& operator=(const SentryImpl&) = delete;

    boost::asio::awaitable<void> run();

  private:
    void setup_node_key();
    boost::asio::awaitable<void> run_tasks();
    boost::asio::awaitable<void> start_status_manager();
    boost::asio::awaitable<void> start_server();
    boost::asio::awaitable<void> start_discovery();
    boost::asio::awaitable<void> start_peer_manager();
    boost::asio::awaitable<void> start_message_sender();
    boost::asio::awaitable<void> start_message_receiver();
    boost::asio::awaitable<void> start_peer_manager_api();
    boost::asio::awaitable<void> start_rpc_server();
    std::unique_ptr<rlpx::Protocol> make_protocol();
    std::function<std::unique_ptr<rlpx::Protocol>()> protocol_factory();
    std::unique_ptr<rlpx::Client> make_client();
    std::function<std::unique_ptr<rlpx::Client>()> client_factory();
    [[nodiscard]] std::string client_id() const;
    common::EnodeUrl make_node_url() const;
    api::api_common::NodeInfo make_node_info() const;
    std::function<api::api_common::NodeInfo()> node_info_provider() const;

    Settings settings_;
    std::optional<NodeKey> node_key_;
    silkworm::rpc::ServerContextPool& context_pool_;

    StatusManager status_manager_;

    rlpx::Server rlpx_server_;
    discovery::Discovery discovery_;
    PeerManager peer_manager_;

    MessageSender message_sender_;
    std::shared_ptr<MessageReceiver> message_receiver_;
    std::shared_ptr<PeerManagerApi> peer_manager_api_;

    rpc::server::Server rpc_server_;
};

static silkworm::rpc::ServerConfig make_server_config(const Settings& settings) {
    silkworm::rpc::ServerConfig config;
    config.set_address_uri(settings.api_address);
    config.set_num_contexts(settings.num_contexts);
    config.set_wait_mode(settings.wait_mode);
    return config;
}

static api::router::ServiceRouter make_service_router(
    concurrency::Channel<eth::StatusData>& status_channel,
    MessageSender& message_sender,
    MessageReceiver& message_receiver,
    PeerManagerApi& peer_manager_api,
    std::function<api::api_common::NodeInfo()> node_info_provider) {
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
      discovery_(settings_.static_peers),
      peer_manager_(context_pool_.next_io_context(), settings_.max_peers, context_pool_),
      message_sender_(context_pool_.next_io_context()),
      message_receiver_(std::make_shared<MessageReceiver>(context_pool_.next_io_context(), settings_.max_peers)),
      peer_manager_api_(std::make_shared<PeerManagerApi>(context_pool_.next_io_context(), peer_manager_)),
      rpc_server_(make_server_config(settings_), make_service_router(status_manager_.status_channel(), message_sender_, *message_receiver_, *peer_manager_api_, node_info_provider())) {
}

boost::asio::awaitable<void> SentryImpl::run() {
    using namespace common::awaitable_wait_for_all;

    setup_node_key();

    return (run_tasks() && start_rpc_server());
}

void SentryImpl::setup_node_key() {
    DataDirectory data_dir{settings_.data_dir_path, true};
    NodeKey node_key = node_key_get_or_generate(settings_.node_key, data_dir);
    node_key_ = {node_key};
}

boost::asio::awaitable<void> SentryImpl::run_tasks() {
    using namespace common::awaitable_wait_for_all;

    log::Info() << "Waiting for status message...";
    co_await status_manager_.wait_for_status();

    co_await (
        start_status_manager() &&
        start_server() &&
        start_discovery() &&
        start_peer_manager() &&
        start_message_sender() &&
        start_message_receiver() &&
        start_peer_manager_api());
}

std::unique_ptr<rlpx::Protocol> SentryImpl::make_protocol() {
    return std::unique_ptr<rlpx::Protocol>(new eth::Protocol(status_manager_.status_provider()));
}

std::function<std::unique_ptr<rlpx::Protocol>()> SentryImpl::protocol_factory() {
    return [this] { return this->make_protocol(); };
}

boost::asio::awaitable<void> SentryImpl::start_status_manager() {
    return status_manager_.start();
}

boost::asio::awaitable<void> SentryImpl::start_server() {
    return rlpx_server_.start(context_pool_, node_key_.value(), client_id(), protocol_factory());
}

std::unique_ptr<rlpx::Client> SentryImpl::make_client() {
    return std::make_unique<rlpx::Client>(node_key_.value(), client_id(), settings_.port, protocol_factory());
}

std::function<std::unique_ptr<rlpx::Client>()> SentryImpl::client_factory() {
    return [this] { return this->make_client(); };
}

boost::asio::awaitable<void> SentryImpl::start_discovery() {
    return discovery_.start();
}

boost::asio::awaitable<void> SentryImpl::start_peer_manager() {
    return peer_manager_.start(rlpx_server_, discovery_, client_factory());
}

boost::asio::awaitable<void> SentryImpl::start_message_sender() {
    return message_sender_.start(peer_manager_);
}

boost::asio::awaitable<void> SentryImpl::start_message_receiver() {
    return MessageReceiver::start(message_receiver_, peer_manager_);
}

boost::asio::awaitable<void> SentryImpl::start_peer_manager_api() {
    return PeerManagerApi::start(peer_manager_api_);
}

boost::asio::awaitable<void> SentryImpl::start_rpc_server() {
    return rpc_server_.async_run();
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

common::EnodeUrl SentryImpl::make_node_url() const {
    return common::EnodeUrl{
        node_key_.value().public_key(),
        // TODO: need an external IP here
        rlpx_server_.ip(),
        settings_.port,
    };
}

api::api_common::NodeInfo SentryImpl::make_node_info() const {
    return {
        make_node_url(),
        node_key_.value().public_key(),
        client_id(),
        rlpx_server_.listen_endpoint(),
        settings_.port,
    };
}

std::function<api::api_common::NodeInfo()> SentryImpl::node_info_provider() const {
    return [this] { return this->make_node_info(); };
}

Sentry::Sentry(Settings settings, silkworm::rpc::ServerContextPool& context_pool)
    : p_impl_(std::make_unique<SentryImpl>(std::move(settings), context_pool)) {
}

Sentry::~Sentry() {
    log::Trace() << "silkworm::sentry::Sentry::~Sentry";
}

boost::asio::awaitable<void> Sentry::run() {
    return p_impl_->run();
}

}  // namespace silkworm::sentry
