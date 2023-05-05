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

#pragma once

#include <functional>
#include <memory>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

#include <silkworm/sentry/api/api_common/sentry_client.hpp>
#include <silkworm/sentry/eth/status_data.hpp>

namespace silkworm::sentry {

class SessionSentryClientImpl;

class SessionSentryClient : public api::api_common::SentryClient {
  public:
    using StatusDataProvider = std::function<boost::asio::awaitable<eth::StatusData>(uint8_t eth_version)>;

    SessionSentryClient(
        std::shared_ptr<api::api_common::SentryClient> sentry_client,
        StatusDataProvider status_data_provider);
    ~SessionSentryClient() override;

    boost::asio::awaitable<std::shared_ptr<api::api_common::Service>> service() override;

    [[nodiscard]] bool is_ready() override;
    void on_disconnect(std::function<boost::asio::awaitable<void>()> callback) override;
    boost::asio::awaitable<void> reconnect() override;

  private:
    std::unique_ptr<SessionSentryClientImpl> p_impl_;
};

}  // namespace silkworm::sentry
