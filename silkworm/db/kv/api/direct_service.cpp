// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "direct_service.hpp"

#include <gsl/util>

#include "endpoint/state_changes_call.hpp"
#include "local_transaction.hpp"

namespace silkworm::db::kv::api {

DirectService::DirectService(ServiceRouter router, DataStoreRef data_store, const ChainConfig& chain_config, StateCache* state_cache)
    : router_{router},
      data_store_{std::move(data_store)},
      chain_config_{chain_config},
      state_cache_{state_cache} {}

// rpc Version(google.protobuf.Empty) returns (types.VersionReply);
Task<Version> DirectService::version() {
    co_return kCurrentVersion;
}

// rpc Tx(stream Cursor) returns (stream Pair);
Task<std::unique_ptr<Transaction>> DirectService::begin_transaction() {
    co_return std::make_unique<LocalTransaction>(data_store_, chain_config_, state_cache_);
}

// rpc StateChanges(StateChangeRequest) returns (stream StateChangeBatch);
Task<void> DirectService::state_changes(const api::StateChangeOptions& options, api::StateChangeConsumer consumer) {
    auto executor = co_await boost::asio::this_coro::executor;
    api::StateChangesCall call{options, executor};

    auto unsubscribe_signal = call.unsubscribe_signal();
    [[maybe_unused]] auto _ = gsl::finally([=]() { unsubscribe_signal->notify(); });

    co_await router_.state_changes_calls_channel.send(call);
    auto channel = co_await call.result();

    // Loop until stream completed (i.e. no message received) or cancelled exception
    bool stream_completed{false};
    while (!stream_completed) {
        auto message = co_await channel->receive();
        if (!message) {
            stream_completed = true;
        }
        co_await consumer(std::move(message));
    }
}

}  // namespace silkworm::db::kv::api
