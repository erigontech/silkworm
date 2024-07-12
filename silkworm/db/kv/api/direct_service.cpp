/*
   Copyright 2024 The Silkworm Authors

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

#include "direct_service.hpp"

#include <gsl/util>

#include "endpoint/state_changes_call.hpp"

namespace silkworm::db::kv::api {

// rpc Version(google.protobuf.Empty) returns (types.VersionReply);
Task<Version> DirectService::version() {
    co_return kCurrentVersion;
}

// rpc Tx(stream Cursor) returns (stream Pair);
Task<std::unique_ptr<Transaction>> DirectService::begin_transaction() {
    // TODO(canepat) implement
    co_return nullptr;
}

// rpc StateChanges(StateChangeRequest) returns (stream StateChangeBatch);
Task<void> DirectService::state_changes(const api::StateChangeOptions& options, api::StateChangeConsumer consumer) {
    auto executor = co_await ThisTask::executor;
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

/** Temporal Point Queries **/

// rpc HistoryGet(HistoryGetReq) returns (HistoryGetReply);
Task<HistoryPointResult> DirectService::get_history(const HistoryPointQuery&) {
    // TODO(canepat) implement
    co_return HistoryPointResult{};
}

// rpc DomainGet(DomainGetReq) returns (DomainGetReply);
Task<DomainPointResult> DirectService::get_domain(const DomainPointQuery&) {
    // TODO(canepat) implement
    co_return DomainPointResult{};
}

/** Temporal Range Queries **/

// rpc IndexRange(IndexRangeReq) returns (IndexRangeReply);
Task<IndexRangeResult> DirectService::get_index_range(const IndexRangeQuery&) {
    // TODO(canepat) implement
    co_return IndexRangeResult{};
}

// rpc HistoryRange(HistoryRangeReq) returns (Pairs);
Task<HistoryRangeResult> DirectService::get_history_range(const HistoryRangeQuery&) {
    // TODO(canepat) implement
    co_return HistoryRangeResult{};
}

// rpc DomainRange(DomainRangeReq) returns (Pairs);
Task<DomainRangeResult> DirectService::get_domain_range(const DomainRangeQuery&) {
    // TODO(canepat) implement
    co_return DomainRangeResult{};
}

}  // namespace silkworm::db::kv::api
