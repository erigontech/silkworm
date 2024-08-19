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

#include "service_router.hpp"

#include <silkworm/infra/concurrency/spawn.hpp>

namespace silkworm::db::kv::api {

using namespace boost::asio;

Task<void> StateChangeRunner::run(std::shared_ptr<StateChangeRunner> self) {
    auto run = self->handle_calls();
    co_await concurrency::spawn_and_async_wait(self->strand_, std::move(run));
}

StateChangeRunner::StateChangeRunner(const boost::asio::any_io_executor& executor)
    : state_changes_calls_channel_{executor}, strand_{executor} {}

Task<void> StateChangeRunner::handle_calls() {
    auto executor = co_await ThisTask::executor;

    // Loop until receive() throws a cancelled exception
    while (true) {
        auto call = co_await state_changes_calls_channel_.receive();

        auto state_changes_channel = std::make_shared<StateChangeChannel>(executor);

        call.set_result(state_changes_channel);
    }
}

}  // namespace silkworm::db::kv::api
