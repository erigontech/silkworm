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

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/system/system_error.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/test_util/task_runner.hpp>

namespace silkworm::concurrency {

using namespace std::chrono_literals;
using namespace boost::asio;

TEST_CASE("Channel.close_and_send") {
    test_util::TaskRunner runner;
    Channel<int> channel{runner.executor()};
    channel.close();
    // boost::asio::experimental::error::channel_errors::channel_closed
    CHECK_THROWS_AS(runner.run(channel.send(1)), boost::system::system_error);
}

TEST_CASE("Channel.close_and_receive") {
    test_util::TaskRunner runner;
    Channel<int> channel{runner.executor()};
    channel.close();
    // boost::asio::experimental::error::channel_errors::channel_closed
    CHECK_THROWS_AS(runner.run(channel.receive()), boost::system::system_error);
}

}  // namespace silkworm::concurrency
