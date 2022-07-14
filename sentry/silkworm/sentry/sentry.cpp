/*
Copyright 2020-2022 The Silkworm Authors

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
#include <future>

#include <silkworm/concurrency/coroutine.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/use_future.hpp>
#include <grpc/grpc.h>

#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/concurrency/cancellation_signal.hpp>
#include <silkworm/rpc/server/server_context_pool.hpp>

#include "rlpx/server.hpp"
#include "rpc/server.hpp"
#include "node_key_config.hpp"

namespace silkworm::sentry {

using namespace std;
using namespace boost::asio::experimental::awaitable_operators;

class SentryImpl final {
  public:
    explicit SentryImpl(Settings settings);

    SentryImpl(const SentryImpl&) = delete;
    SentryImpl& operator=(const SentryImpl&) = delete;

    void start();
    void stop();
    void join();

  private:
    void setup_shutdown_on_signals(boost::asio::io_context&);

    Settings settings_;
    silkworm::rpc::ServerContextPool context_pool_;

    rlpx::Server rlpx_server_;
    optional<future<std::variant<std::monostate, std::monostate>>> rlpx_server_task_;
    rpc::Server rpc_server_;

    optional<unique_ptr<boost::asio::signal_set>> shutdown_signals_;
    optional<unique_ptr<concurrency::CancellationSignal>> stop_signal_;
};

static silkworm::rpc::ServerConfig make_server_config(const Settings& settings) {
    silkworm::rpc::ServerConfig config;
    config.set_address_uri(settings.api_address);
    config.set_num_contexts(settings.num_contexts);
    config.set_wait_mode(settings.wait_mode);
    return config;
}

class DummyServerCompletionQueue : public grpc::ServerCompletionQueue {
};

SentryImpl::SentryImpl(Settings settings)
    : settings_(std::move(settings)),
      context_pool_(settings_.num_contexts),
      rlpx_server_("0.0.0.0", settings_.port),
      rpc_server_(make_server_config(settings_)) {
    for (size_t i = 0; i < settings_.num_contexts; i++) {
        context_pool_.add_context(make_unique<DummyServerCompletionQueue>(), settings_.wait_mode);
    }
}

void SentryImpl::start() {
    DataDirectory data_dir{settings_.data_dir_path, true};
    [[maybe_unused]]
    NodeKey node_key = node_key_get_or_generate(settings_.node_key, data_dir);

    rpc_server_.build_and_start();

    auto& rlpx_io_context = context_pool_.next_io_context();
    stop_signal_ = { std::make_unique<concurrency::CancellationSignal>(rlpx_io_context) };
    rlpx_server_task_ = boost::asio::co_spawn(
            rlpx_io_context,
            rlpx_server_.start(rlpx_io_context) || stop_signal_.value()->await(),
            boost::asio::use_future);

    setup_shutdown_on_signals(context_pool_.next_io_context());

    context_pool_.start();
}

void SentryImpl::stop() {
    rpc_server_.shutdown();

    if (stop_signal_) {
        stop_signal_.value()->emit();
    }
}

void SentryImpl::join() {
    rpc_server_.join();

    if (rlpx_server_task_) {
        rlpx_server_task_->wait();
    }

    context_pool_.stop();
    context_pool_.join();
}

void SentryImpl::setup_shutdown_on_signals(boost::asio::io_context& io_context) {
    shutdown_signals_ = { make_unique<boost::asio::signal_set>(io_context, SIGINT, SIGTERM) };
    shutdown_signals_.value()->async_wait([&](const boost::system::error_code& error, int signal_number) {
        log::Info() << "\n";
        log::Info() << "Signal caught, error: " << error << " number: " << signal_number;
        this->stop();
    });
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
