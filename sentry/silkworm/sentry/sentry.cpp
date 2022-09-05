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

#include <future>
#include <string>

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <grpc/grpc.h>

#include <silkworm/buildinfo.h>
#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/rpc/server/server_context_pool.hpp>

#include "node_key_config.hpp"
#include "rlpx/client.hpp"
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
    void setup_shutdown_on_signals(asio::io_context&);
    [[nodiscard]] std::string client_id() const;

    Settings settings_;
    silkworm::rpc::ServerContextPool context_pool_;

    rlpx::Server rlpx_server_;
    std::promise<void> rlpx_server_task_;
    asio::cancellation_signal rlpx_server_stop_signal_;

    rlpx::Client rlpx_client_;
    std::promise<void> rlpx_client_task_;
    asio::cancellation_signal rlpx_client_stop_signal_;

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
      context_pool_(settings_.num_contexts),
      rlpx_server_("0.0.0.0", settings_.port),
      rlpx_client_(settings_.static_peers),
      rpc_server_(make_server_config(settings_)) {
    for (size_t i = 0; i < settings_.num_contexts; i++) {
        context_pool_.add_context(make_unique<DummyServerCompletionQueue>(), settings_.wait_mode);
    }
}

void SentryImpl::start() {
    DataDirectory data_dir{settings_.data_dir_path, true};
    NodeKey node_key = node_key_get_or_generate(settings_.node_key, data_dir);

    rpc_server_.build_and_start();

    auto rlpx_server_task_completion = [&](const std::exception_ptr& ex_ptr) {
        rethrow_unless_cancelled(ex_ptr);
        this->rlpx_server_task_.set_value();
    };
    asio::co_spawn(
        context_pool_.next_io_context(),
        rlpx_server_.start(context_pool_, node_key, client_id()),
        asio::bind_cancellation_slot(rlpx_server_stop_signal_.slot(), rlpx_server_task_completion));

    auto rlpx_client_task_completion = [&](const std::exception_ptr& ex_ptr) {
        rethrow_unless_cancelled(ex_ptr);
        this->rlpx_client_task_.set_value();
    };
    asio::co_spawn(
        context_pool_.next_io_context(),
        rlpx_client_.start(node_key, client_id(), settings_.port),
        asio::bind_cancellation_slot(rlpx_client_stop_signal_.slot(), rlpx_client_task_completion));

    setup_shutdown_on_signals(context_pool_.next_io_context());

    context_pool_.start();
}

void SentryImpl::stop() {
    rpc_server_.shutdown();
    rlpx_server_stop_signal_.emit(asio::cancellation_type::all);
    rlpx_client_stop_signal_.emit(asio::cancellation_type::all);
}

void SentryImpl::join() {
    rpc_server_.join();
    rlpx_server_task_.get_future().wait();
    rlpx_client_task_.get_future().wait();

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
