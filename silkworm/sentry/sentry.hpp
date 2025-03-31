// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/infra/concurrency/executor_pool.hpp>

#include "api/common/sentry_client.hpp"
#include "settings.hpp"

struct buildinfo;

namespace silkworm::sentry {

class SentryImpl;

class Sentry final : public api::SentryClient {
  public:
    explicit Sentry(Settings settings, concurrency::ExecutorPool& executor_pool);
    ~Sentry() override;

    Sentry(const Sentry&) = delete;
    Sentry& operator=(const Sentry&) = delete;

    Task<void> run();

    Task<std::shared_ptr<api::Service>> service() override;
    bool is_ready() override;
    void on_disconnect(std::function<Task<void>()> callback) override;
    Task<void> reconnect() override;

  private:
    std::unique_ptr<SentryImpl> p_impl_;
};

}  // namespace silkworm::sentry
