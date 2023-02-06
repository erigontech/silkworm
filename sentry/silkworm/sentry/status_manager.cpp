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

#include "status_manager.hpp"

#include <silkworm/common/log.hpp>

namespace silkworm::sentry {

boost::asio::awaitable<void> StatusManager::wait_for_status() {
    auto status = co_await status_channel_.receive();
    status_.set(status);
    log::Info() << "Status received: network ID = " << status.message.network_id;
}

boost::asio::awaitable<void> StatusManager::start() {
    // loop until wait_for_status() throws a cancelled exception
    while (true) {
        co_await wait_for_status();
    }
}

}  // namespace silkworm::sentry
