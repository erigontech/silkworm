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

Task<void> reconnect_channel(grpc::Channel& channel) {
    bool is_stopped = false;

    std::function<void()> run = [&] {
        bool is_connected = false;
        while (!is_connected && !is_stopped && (channel.GetState(false) != GRPC_CHANNEL_SHUTDOWN)) {
            log::Info() << "Reconnecting grpc::Channel...";
            auto deadline = gpr_time_add(gpr_now(GPR_CLOCK_REALTIME), gpr_time_from_seconds(5, GPR_TIMESPAN));
            is_connected = channel.WaitForConnected(deadline);
        }
    };

    std::function<void()> stop = [&] {
        is_stopped = true;
    };

    co_await concurrency::async_thread(std::move(run), std::move(stop), "channel-rec");
}

}  // namespace silkworm::rpc
