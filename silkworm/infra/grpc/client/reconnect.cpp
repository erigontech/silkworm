// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "reconnect.hpp"

#include <functional>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/async_thread.hpp>

namespace silkworm::rpc {

bool is_disconnect_error(const grpc::Status& status, grpc::Channel& channel) {
    auto code = status.error_code();
    return (code == grpc::StatusCode::UNAVAILABLE) ||
           ((code == grpc::StatusCode::DEADLINE_EXCEEDED) && (channel.GetState(false) != GRPC_CHANNEL_READY) && (channel.GetState(false) != GRPC_CHANNEL_SHUTDOWN));
}

// min_sec, min_sec*2, min_sec*4, ... max_sec, max_sec, ...
int64_t backoff_timeout(size_t attempt, int64_t min_msec, int64_t max_msec) {
    if (attempt >= 20) return max_msec;
    return std::min(min_msec << attempt, max_msec);
}

Task<void> reconnect_channel(grpc::Channel& channel, std::string log_prefix, int64_t min_msec, int64_t max_msec) {
    bool is_stopped = false;

    std::function<void()> run = [&] {
        bool is_connected = false;
        size_t attempt = 0;
        while (!is_connected && !is_stopped && (channel.GetState(false) != GRPC_CHANNEL_SHUTDOWN)) {
            SILK_INFO_M(log_prefix) << "Reconnecting gRPC channel...";
            auto timeout = backoff_timeout(attempt++, min_msec, max_msec);
            auto deadline = gpr_time_add(gpr_now(GPR_CLOCK_REALTIME), gpr_time_from_millis(timeout, GPR_TIMESPAN));
            is_connected = channel.WaitForConnected(deadline);
        }
    };

    std::function<void()> stop = [&] {
        is_stopped = true;
    };

    co_await concurrency::async_thread(std::move(run), std::move(stop), "channel-rec");
}

}  // namespace silkworm::rpc
