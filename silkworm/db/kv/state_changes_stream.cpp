// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "state_changes_stream.hpp"

#include <boost/system/error_code.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>
#include <silkworm/infra/grpc/client/call.hpp>

namespace silkworm::db::kv {

StateChangesStream::StateChangesStream(rpc::ClientContext& context, api::Client& client)
    : ioc_(*context.ioc()),
      client_(client),
      cache_(must_use_shared_service<api::StateCache>(ioc_)) {}

std::future<void> StateChangesStream::open() {
    return concurrency::spawn_future(ioc_, run());
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
