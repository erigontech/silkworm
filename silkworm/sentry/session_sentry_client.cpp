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

#include "session_sentry_client.hpp"

#include <mutex>

#include <silkworm/infra/concurrency/awaitable_condition_variable.hpp>

namespace silkworm::sentry {

using namespace boost::asio;

class SessionSentryClientImpl : public api::api_common::SentryClient {
  public:
    using StatusDataProvider = std::function<boost::asio::awaitable<eth::StatusData>(uint8_t eth_version)>;

    SessionSentryClientImpl(
        std::shared_ptr<api::api_common::SentryClient> sentry_client,
        StatusDataProvider status_data_provider)
        : sentry_client_(std::move(sentry_client)),
          status_data_provider_(std::move(status_data_provider)) {
        sentry_client_->on_disconnect([this] { return this->handle_disconnect(); });
    }

    ~SessionSentryClientImpl() override {
        sentry_client_->on_disconnect([]() -> awaitable<void> { co_return; });
    }

    boost::asio::awaitable<std::shared_ptr<api::api_common::Service>> service() override {
        // TODO: synchronize
        auto waiter = session_started_cond_var_.waiter();
        co_await waiter();

        co_return (co_await sentry_client_->service());
    }

    void on_disconnect(std::function<boost::asio::awaitable<void>()> /*callback*/) override {
        assert(false);
    }

  private:
    awaitable<void> start_session() {
        auto service = co_await sentry_client_->service();
        auto eth_version = co_await service->handshake();
        auto status_data = co_await status_data_provider_(eth_version);
        co_await service->set_status(std::move(status_data));
        // TODO: synchronize
        session_started_cond_var_.notify_all();
    }

    awaitable<void> handle_disconnect() {
        co_return;
    }

    std::shared_ptr<api::api_common::SentryClient> sentry_client_;
    StatusDataProvider status_data_provider_;
    concurrency::AwaitableConditionVariable session_started_cond_var_;
};

SessionSentryClient::SessionSentryClient(
    std::shared_ptr<api::api_common::SentryClient> sentry_client,
    StatusDataProvider status_data_provider)
    : p_impl_(std::make_unique<SessionSentryClientImpl>(sentry_client, status_data_provider)) {
}

SessionSentryClient::~SessionSentryClient() {
    [[maybe_unused]] int non_trivial_destructor;  // silent clang-tidy
}

awaitable<std::shared_ptr<api::api_common::Service>> SessionSentryClient::service() {
    return p_impl_->service();
}

void SessionSentryClient::on_disconnect(std::function<boost::asio::awaitable<void>()> callback) {
    p_impl_->on_disconnect(callback);
}

}  // namespace silkworm::sentry
