// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include "service.hpp"

namespace silkworm::sentry::api {

struct SentryClient {
    virtual ~SentryClient() = default;

    virtual Task<std::shared_ptr<Service>> service() = 0;

    //! Connected or just created an ready to handle calls. service() is unlikely to block for long.
    virtual bool is_ready() = 0;
    virtual void on_disconnect(std::function<Task<void>()> callback) = 0;
    virtual Task<void> reconnect() = 0;
};

}  // namespace silkworm::sentry::api
