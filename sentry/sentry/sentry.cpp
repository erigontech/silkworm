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
#include <boost/asio/signal_set.hpp>
#include <boost/asio/io_context.hpp>
#include <silkworm/common/directories.hpp>
#include "rpc/server.hpp"
#include "node_key_config.hpp"

namespace silkworm::sentry {

using namespace std;

class SentryImpl final {
  public:
    explicit SentryImpl(Options options);

    SentryImpl(const SentryImpl&) = delete;
    SentryImpl& operator=(const SentryImpl&) = delete;

    void start();
    void stop();
    void join();

  private:
    void setup_shutdown_on_signals(boost::asio::io_context&);

    Options options_;
    rpc::Server rpc_server_;
    optional<unique_ptr<boost::asio::signal_set>> shutdown_signals_;
};

static silkworm::rpc::ServerConfig make_server_config(const Options& options) {
    silkworm::rpc::ServerConfig config;
    config.set_address_uri(options.api_address);
    config.set_num_contexts(options.num_contexts);
    config.set_wait_mode(options.wait_mode);
    return config;
}

SentryImpl::SentryImpl(Options options)
    : options_(std::move(options)),
      rpc_server_(make_server_config(options_)) {
}

void SentryImpl::start() {
    DataDirectory data_dir{options_.data_dir_path, true};
    [[maybe_unused]]
    NodeKey node_key = node_key_get_or_generate(options_.node_key, data_dir);

    rpc_server_.build_and_start();
    setup_shutdown_on_signals(rpc_server_.next_io_context());
}

void SentryImpl::stop() {
    rpc_server_.shutdown();
}

void SentryImpl::join() {
    rpc_server_.join();
}

void SentryImpl::setup_shutdown_on_signals(boost::asio::io_context& io_context) {
    shutdown_signals_ = { make_unique<boost::asio::signal_set>(io_context, SIGINT, SIGTERM) };
    shutdown_signals_.value()->async_wait([&](const boost::system::error_code& error, int signal_number) {
        log::Info() << "\n";
        log::Info() << "Signal caught, error: " << error << " number: " << signal_number;
        this->stop();
    });
}

Sentry::Sentry(Options options)
    : p_impl_(make_unique<SentryImpl>(std::move(options))) {
}

Sentry::~Sentry() {
    log::Trace() << "silkworm::sentry::Sentry::~Sentry";
}

void Sentry::start() { p_impl_->start(); }
void Sentry::stop() { p_impl_->stop(); }
void Sentry::join() { p_impl_->join(); }

}  // namespace silkworm::sentry
