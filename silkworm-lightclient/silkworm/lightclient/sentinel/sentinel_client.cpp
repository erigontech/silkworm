/*
   Copyright 2022 The Silkworm Authors

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

#include "sentinel_client.hpp"

#include <thread>

#include <silkworm/common/log.hpp>
#include <silkworm/sentry/common/timeout.hpp>

namespace silkworm::cl::sentinel {

using namespace std::chrono;
using namespace boost::asio;

LocalClient::LocalClient(Server* local_server) : local_server_(local_server) {}

awaitable<void> LocalClient::start() {
    sentry::common::Timeout timeout{1'000'000s};
    co_await timeout();
}

awaitable<LightClientBootstrapPtr> LocalClient::bootstrap_request_v1(const Hash32& root) {
    RequestData request{};
    const ResponseData response = co_await local_server_->send_request(request);

    log::Info() << "BEFORE timeout 1s";
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(1s);
    log::Info() << "AFTER timeout 1s";

    // TODO(canepat) implement
    co_return LightClientBootstrapPtr{};
}

awaitable<void> RemoteClient::start() {
    sentry::common::Timeout timeout{1'000'000s};
    co_await timeout();
}

awaitable<LightClientBootstrapPtr> RemoteClient::bootstrap_request_v1(const Hash32& root) {
    // TODO(canepat) implement
    co_return LightClientBootstrapPtr{};
}

}  // namespace silkworm::cl::sentinel
