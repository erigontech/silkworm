// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "coroutine.hpp"

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>

namespace silkworm::concurrency {

using namespace boost::asio;

Task<int> coroutine_return_123() {
    co_return 123;
}

TEST_CASE("check configuration", "[silkworm][infra][concurrency]") {
#if __has_include(<coroutine>)
#ifdef BOOST_ASIO_HAS_CO_AWAIT
    CHECK(true);
#else
    CHECK(false);
#endif  // BOOST_ASIO_HAS_CO_AWAIT
#ifdef BOOST_ASIO_HAS_STD_COROUTINE
    CHECK(true);
#else
    CHECK(false);
#endif  // BOOST_ASIO_HAS_STD_COROUTINE
#endif  // __has_include(<coroutine>)
    CHECK(&typeid(std::coroutine_handle<void>) != nullptr);
    CHECK(&typeid(std::suspend_always) != nullptr);
    CHECK(&typeid(std::suspend_never) != nullptr);
}

TEST_CASE("coroutine co_return", "[silkworm][infra][concurrency]") {
    io_context ioc;
    auto task = co_spawn(
        ioc,
        coroutine_return_123(),
        boost::asio::use_future);

    size_t work_count{0};
    do {
        work_count = ioc.poll_one();
    } while (work_count > 0);
    CHECK(task.get() == 123);
}

}  // namespace silkworm::concurrency
