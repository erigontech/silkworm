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

#include "sentinel_server.hpp"

#include <thread>

#include <silkworm/sentry/common/timeout.hpp>

namespace silkworm::cl::sentinel {

using namespace std::chrono;
using namespace boost::asio;

awaitable<void> Server::start() {
    sentry::common::Timeout timeout{1'000'000s};
    co_await timeout();
}

awaitable<ResponseData> Server::send_request(const RequestData& /*request*/) {
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(1s);
    co_return ResponseData{};
}

}  // namespace silkworm::cl::sentinel
