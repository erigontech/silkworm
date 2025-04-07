// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "sleep.hpp"

#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace silkworm {

using namespace boost::asio;

Task<void> sleep(std::chrono::milliseconds duration) {
    auto executor = co_await this_coro::executor;
    steady_timer timer(executor);
    timer.expires_after(duration);
    co_await timer.async_wait(use_awaitable);
}

}  // namespace silkworm
