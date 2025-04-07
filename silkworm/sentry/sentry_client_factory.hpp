// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <silkworm/infra/concurrency/executor_pool.hpp>
#include <silkworm/infra/grpc/common/grpc_context_pool.hpp>

#include "api/common/sentry_client.hpp"
#include "sentry.hpp"
#include "session_sentry_client.hpp"
#include "settings.hpp"

namespace silkworm::sentry {

struct SentryClientFactory {
    using SentryClientPtr = std::shared_ptr<sentry::api::SentryClient>;
    using SentryServerPtr = std::shared_ptr<sentry::Sentry>;
    using SentryPtrPair = std::tuple<SentryClientPtr, SentryServerPtr>;

    static SentryPtrPair make_sentry(
        Settings sentry_settings,
        const std::vector<std::string>& remote_sentry_addresses,
        concurrency::ExecutorPool& executor_pool,
        rpc::GrpcContextPool& grpc_context_pool,
        SessionSentryClient::StatusDataProvider eth_status_data_provider);
};

}  // namespace silkworm::sentry
