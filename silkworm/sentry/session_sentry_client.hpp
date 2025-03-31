// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/sentry/api/common/sentry_client.hpp>
#include <silkworm/sentry/eth/status_data.hpp>

namespace silkworm::sentry {

class SessionSentryClientImpl;

class SessionSentryClient : public api::SentryClient {
  public:
    using StatusDataProvider = std::function<Task<eth::StatusData>(uint8_t eth_version)>;

    SessionSentryClient(
        std::shared_ptr<api::SentryClient> sentry_client,
        StatusDataProvider status_data_provider);
    ~SessionSentryClient() override;

    Task<std::shared_ptr<api::Service>> service() override;

    bool is_ready() override;
    void on_disconnect(std::function<Task<void>()> callback) override;
    Task<void> reconnect() override;

  private:
    std::unique_ptr<SessionSentryClientImpl> p_impl_;
};

}  // namespace silkworm::sentry
