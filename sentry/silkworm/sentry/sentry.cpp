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
#include <future>
#include <memory>
#include <string>

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/rpc/server/server_context_pool.hpp>
#include <silkworm/sentry/common/atomic_value.hpp>
#include <silkworm/sentry/common/channel.hpp>

#include "eth/protocol.hpp"
#include "eth/status_data.hpp"
#include "message_receiver.hpp"
#include "message_sender.hpp"
#include "node_key_config.hpp"
#include "peer_manager.hpp"
#include "rlpx/client.hpp"
#include "rlpx/protocol.hpp"
#include "rlpx/server.hpp"
#include "rpc/server.hpp"

namespace silkworm::sentry {

using namespace std;
using namespace boost;

class SentryImpl final {
  public:
    explicit SentryImpl(Settings settings);

    SentryImpl(const SentryImpl&) = delete;
    SentryImpl& operator=(const SentryImpl&) = delete;

    void start();
    void stop();
    void join();

  private:
    void setup_node_key();
    void setup_shutdown_on_signals(asio::io_context&);
    void spawn_run_tasks();
    boost::asio::awaitable<void> run_tasks();
    boost::asio::awaitable<void> start_server();
    boost::asio::awaitable<void> start_client();
    boost::asio::awaitable<void> start_peer_manager();
    boost::asio::awaitable<void> start_message_sender();
    boost::asio::awaitable<void> start_message_receiver();
    std::unique_ptr<rlpx::Protocol> make_protocol();
    std::function<std::unique_ptr<rlpx::Protocol>()> protocol_factory();
    [[nodiscard]] std::string client_id() const;

    Settings settings_;
    std::optional<NodeKey> node_key_;
    silkworm::rpc::ServerContextPool context_pool_;

    common::Channel<eth::StatusData> status_channel_;
    optional<common::AtomicValue<eth::StatusData>> status_;

    PeerManager peer_manager_;
    MessageSender message_sender_;
    std::shared_ptr<MessageReceiver> message_receiver_;

    std::promise<void> tasks_promise_;
    asio::cancellation_signal tasks_stop_signal_;

    rlpx::Server rlpx_server_;
    rlpx::Client rlpx_client_;

    rpc::Server rpc_server_;

    optional<unique_ptr<asio::signal_set>> shutdown_signals_;
};

static silkworm::rpc::ServerConfig make_server_config(const Settings& settings) {
    silkworm::rpc::ServerConfig config;
    config.set_address_uri(settings.api_address);
    config.set_num_contexts(settings.num_contexts);
    config.set_wait_mode(settings.wait_mode);
    return config;
}

static rpc::common::ServiceState make_service_state(
    common::Channel<eth::StatusData>& status_channel,
    MessageSender& message_sender,
    MessageReceiver& message_receiver) {
    return rpc::common::ServiceState{
        eth::Protocol::kVersion,
        status_channel,
        message_sender.send_message_channel(),
        message_receiver.message_calls_channel(),
    };
}

static void rethrow_unless_cancelled(const std::exception_ptr& ex_ptr) {
    if (!ex_ptr)
        return;
    try {
        std::rethrow_exception(ex_ptr);
    } catch (const boost::system::system_error& e) {
        if (e.code() != boost::system::errc::operation_canceled)
            throw;
    }
}

class DummyServerCompletionQueue : public grpc::ServerCompletionQueue {
};

SentryImpl::SentryImpl(Settings settings)
    : settings_(std::move(settings)),
      context_pool_(settings_.num_contexts, settings_.wait_mode, [] { return make_unique<DummyServerCompletionQueue>(); }),
      status_channel_(context_pool_.next_io_context()),
      peer_manager_(context_pool_.next_io_context()),
      message_sender_(context_pool_.next_io_context()),
      message_receiver_(std::make_shared<MessageReceiver>(context_pool_.next_io_context())),
      rlpx_server_(context_pool_.next_io_context(), "0.0.0.0", settings_.port),
      rlpx_client_(context_pool_.next_io_context(), settings_.static_peers),
      rpc_server_(make_server_config(settings_), make_service_state(status_channel_, message_sender_, *message_receiver_)) {
}

void SentryImpl::start() {
    setup_node_key();
    rpc_server_.build_and_start();

    spawn_run_tasks();

    setup_shutdown_on_signals(context_pool_.next_io_context());

    context_pool_.start();
}

void SentryImpl::setup_node_key() {
    DataDirectory data_dir{settings_.data_dir_path, true};
    NodeKey node_key = node_key_get_or_generate(settings_.node_key, data_dir);
    node_key_ = {node_key};
}

void SentryImpl::spawn_run_tasks() {
    auto completion = [&](const std::exception_ptr& ex_ptr) {
        rethrow_unless_cancelled(ex_ptr);
        this->tasks_promise_.set_value();
    };
    asio::co_spawn(
        context_pool_.next_io_context(),
        run_tasks(),
        asio::bind_cancellation_slot(tasks_stop_signal_.slot(), completion));
}

boost::asio::awaitable<void> SentryImpl::run_tasks() {
    using namespace boost::asio::experimental::awaitable_operators;

    log::Info() << "Waiting for status message...";
    auto status = co_await status_channel_.receive();
    status_.emplace(status);
    log::Info() << "Status received: network ID = " << status.message.network_id;

    co_await (
        start_server() &&
        start_client() &&
        start_peer_manager() &&
        start_message_sender() &&
        start_message_receiver());
}

std::unique_ptr<rlpx::Protocol> SentryImpl::make_protocol() {
    return std::unique_ptr<rlpx::Protocol>(new eth::Protocol(status_->getter()));
}

std::function<std::unique_ptr<rlpx::Protocol>()> SentryImpl::protocol_factory() {
    return [this] { return this->make_protocol(); };
}

boost::asio::awaitable<void> SentryImpl::start_server() {
    return rlpx_server_.start(context_pool_, node_key_.value(), client_id(), protocol_factory());
}

boost::asio::awaitable<void> SentryImpl::start_client() {
    return rlpx_client_.start(context_pool_, node_key_.value(), client_id(), settings_.port, protocol_factory());
}

boost::asio::awaitable<void> SentryImpl::start_peer_manager() {
    return peer_manager_.start(rlpx_server_, rlpx_client_);
}

boost::asio::awaitable<void> SentryImpl::start_message_sender() {
    return message_sender_.start(peer_manager_);
}

boost::asio::awaitable<void> SentryImpl::start_message_receiver() {
    return MessageReceiver::start(message_receiver_, peer_manager_);
}

void SentryImpl::stop() {
    rpc_server_.shutdown();
    tasks_stop_signal_.emit(asio::cancellation_type::all);
}

void SentryImpl::join() {
    rpc_server_.join();
    tasks_promise_.get_future().wait();

    context_pool_.stop();
    context_pool_.join();
}

void SentryImpl::setup_shutdown_on_signals(asio::io_context& io_context) {
    shutdown_signals_ = {make_unique<asio::signal_set>(io_context, SIGINT, SIGTERM)};
    shutdown_signals_.value()->async_wait([&](const boost::system::error_code& error, int signal_number) {
        log::Info() << "\n";
        log::Info() << "Signal caught, error: " << error << " number: " << signal_number;
        this->stop();
    });
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

Sentry::Sentry(Settings settings)
    : p_impl_(make_unique<SentryImpl>(std::move(settings))) {
}

Sentry::~Sentry() {
    log::Trace() << "silkworm::sentry::Sentry::~Sentry";
}

void Sentry::start() { p_impl_->start(); }
void Sentry::stop() { p_impl_->stop(); }
void Sentry::join() { p_impl_->join(); }

}  // namespace silkworm::sentry
