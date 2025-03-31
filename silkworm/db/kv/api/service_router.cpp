// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "service_router.hpp"

#include <silkworm/infra/concurrency/spawn.hpp>

namespace silkworm::db::kv::api {

using namespace boost::asio;

Task<void> StateChangeRunner::run(std::shared_ptr<StateChangeRunner> self) {
    auto run = self->handle_calls();
    co_await concurrency::spawn_task(self->strand_, std::move(run));
}

StateChangeRunner::StateChangeRunner(const boost::asio::any_io_executor& executor)
    : state_changes_calls_channel_{executor}, strand_{executor} {}

Task<void> StateChangeRunner::handle_calls() {
    auto executor = co_await boost::asio::this_coro::executor;

    // Loop until receive() throws a cancelled exception
    while (true) {
        auto call = co_await state_changes_calls_channel_.receive();

        auto state_changes_channel = std::make_shared<StateChangeChannel>(executor);

        call.set_result(state_changes_channel);
    }
}

}  // namespace silkworm::db::kv::api
