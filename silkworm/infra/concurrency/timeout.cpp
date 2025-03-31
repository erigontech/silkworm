// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "timeout.hpp"

#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::concurrency {

Task<void> timeout(
    std::chrono::milliseconds duration,
    const char* source_file_path,
    int source_file_line) {
    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    timer.expires_after(duration);

    try {
        co_await timer.async_wait(boost::asio::use_awaitable);
    } catch (const boost::system::system_error& ex) {
        // if the timeout is cancelled before expiration - it is not an error
        if (ex.code() == boost::system::errc::operation_canceled) {
            co_return;
        }
        throw;
    }

    if (source_file_path) {
        SILK_TRACE << "TimeoutExpiredError in " << source_file_path << ":" << source_file_line;
    }

    throw TimeoutExpiredError();
}

}  // namespace silkworm::concurrency
