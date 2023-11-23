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
        if (ex.code() == boost::system::errc::operation_canceled)
            co_return;
        throw;
    }

    if (source_file_path) {
        log::Trace() << "TimeoutExpiredError in " << source_file_path << ":" << source_file_line;
    }

    throw TimeoutExpiredError();
}

}  // namespace silkworm::concurrency
