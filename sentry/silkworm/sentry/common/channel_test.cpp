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

#include "channel.hpp"

#include <chrono>

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/system/system_error.hpp>
#include <catch2/catch.hpp>

namespace silkworm::sentry::common {

using namespace std::chrono_literals;
using namespace boost::asio;

template <typename TResult>
TResult run(io_context& context, awaitable<TResult> awaitable1) {
    auto task = co_spawn(
        context,
        std::move(awaitable1),
        boost::asio::use_future);

    while (task.wait_for(0s) == std::future_status::timeout) {
        context.poll_one();
    }

    return task.get();
}

TEST_CASE("Channel.close_and_send") {
    io_context context;
    Channel<int> channel{context};
    channel.close();
    // boost::asio::experimental::error::channel_errors::channel_closed
    CHECK_THROWS_AS(run(context, channel.send(1)), boost::system::system_error);
}

TEST_CASE("Channel.close_and_receive") {
    io_context context;
    Channel<int> channel{context};
    channel.close();
    // boost::asio::experimental::error::channel_errors::channel_closed
    CHECK_THROWS_AS(run(context, channel.receive()), boost::system::system_error);
}

}  // namespace silkworm::sentry::common
