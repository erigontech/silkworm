// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
