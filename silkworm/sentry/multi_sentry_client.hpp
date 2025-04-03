// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <vector>

#include <silkworm/sentry/api/common/sentry_client.hpp>

namespace silkworm::sentry {

class MultiSentryClientImpl;

class MultiSentryClient : public api::SentryClient {
  public:
    explicit MultiSentryClient(std::vector<std::shared_ptr<api::SentryClient>> clients);
    ~MultiSentryClient() override;

    Task<std::shared_ptr<api::Service>> service() override;

    bool is_ready() override;
    void on_disconnect(std::function<Task<void>()> callback) override;
    Task<void> reconnect() override;

  private:
    std::shared_ptr<MultiSentryClientImpl> p_impl_;
};

}  // namespace silkworm::sentry
