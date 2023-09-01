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
        std::vector<std::string> remote_sentry_addresses,
        concurrency::ExecutorPool& executor_pool,
        rpc::GrpcContextPool& grpc_context_pool,
        SessionSentryClient::StatusDataProvider eth_status_data_provider);
};

}  // namespace silkworm::sentry
