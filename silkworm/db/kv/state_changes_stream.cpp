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

#include "state_changes_stream.hpp"

#include <boost/asio/use_future.hpp>
#include <boost/system/error_code.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/co_spawn_sw.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/infra/grpc/client/call.hpp>

namespace silkworm::db::kv {

StateChangesStream::StateChangesStream(rpc::ClientContext& context, api::Client& client)
    : scheduler_(*context.io_context()),
      client_(client),
      cache_(must_use_shared_service<api::StateCache>(scheduler_)) {}

std::future<void> StateChangesStream::open() {
    return concurrency::co_spawn(scheduler_, run(), boost::asio::use_future);
}

void StateChangesStream::close() {
    cancellation_token_.signal_cancellation();
    SILK_TRACE << "Close state changes stream: cancellation emitted";
}

Task<void> StateChangesStream::run() {
    SILK_TRACE << "StateChangesStream::run state stream START";

    api::StateChangeOptions options{
        .cancellation_token = &cancellation_token_,
    };

    auto kv_service = client_.service();

    auto state_change_set_consumer = [&](std::optional<api::StateChangeSet> change_set) -> Task<void> {
        if (!change_set) {
            SILK_TRACE << "State changes stream terminated by server";
            co_return;
        }
        cache_->on_new_block(*change_set);
    };
    co_await kv_service->state_changes(options, state_change_set_consumer);

    SILK_TRACE << "StateChangesStream::run state stream END";
}

}  // namespace silkworm::db::kv
