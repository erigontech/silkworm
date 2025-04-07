// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "parallel_group_utils.hpp"

#include <stdexcept>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/experimental/cancellation_condition.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

namespace silkworm::concurrency {

using namespace boost::asio;
using namespace boost::asio::experimental;

static bool is_operation_cancelled_error(const std::exception_ptr& ex_ptr) {
    try {
        std::rethrow_exception(ex_ptr);
    } catch (const boost::system::system_error& e) {
        return (e.code() == boost::system::errc::operation_canceled);
    } catch (...) {
        return false;
    }
}

void rethrow_first_exception_if_any(
    const std::array<std::exception_ptr, 2>& exceptions,
    const std::array<size_t, 2>& order) {
    const auto& ex0 = exceptions[0];
    const auto& ex1 = exceptions[1];

    // no exceptions
    if (!ex0 && !ex1) {
        return;
    }

    // only 1 exception
    if (!ex0) {
        std::rethrow_exception(ex1);
    }
    if (!ex1) {
        std::rethrow_exception(ex0);
    }

    // 2 exceptions, but one of them is an expected operation_canceled caused by aborting a pending branch
    if (is_operation_cancelled_error(ex0)) {
        std::rethrow_exception(ex1);
    }
    if (is_operation_cancelled_error(ex1)) {
        std::rethrow_exception(ex0);
    }

    // 2 unexpected exceptions
    // This is possible if operation_canceled is handled inside a pending operation,
    // but the catch block throws a different error.
    // ex0 was first
    if (order[0] == 0) {
        try {
            std::rethrow_exception(ex1);
        } catch (const std::runtime_error& ex1_ref) {
            try {
                std::rethrow_exception(ex0);
            } catch (...) {
                std::throw_with_nested(ex1_ref);
            }
        }
    }
    // ex1 was first
    else {
        try {
            std::rethrow_exception(ex0);
        } catch (const std::runtime_error& ex0_ref) {
            try {
                std::rethrow_exception(ex1);
            } catch (...) {
                std::throw_with_nested(ex0_ref);
            }
        }
    }
}

void rethrow_first_exception_if_any(
    const std::vector<std::exception_ptr>& exceptions,
    const std::vector<size_t>& order) {
    std::exception_ptr first_cancelled_exception;

    for (size_t i : order) {
        const auto& ex = exceptions[i];
        if (ex) {
            if (!is_operation_cancelled_error(ex)) {
                std::rethrow_exception(ex);
            } else if (!first_cancelled_exception) {
                first_cancelled_exception = ex;
            }
        }
    }

    if (first_cancelled_exception) {
        std::rethrow_exception(first_cancelled_exception);
    }
}

Task<void> generate_parallel_group_task(size_t count, absl::FunctionRef<Task<void>(size_t)> task_factory) {
    if (count == 0) {
        co_return;
    }

    auto executor = co_await this_coro::executor;

    using OperationType = decltype(co_spawn(executor, ([]() -> Task<void> { co_return; })(), deferred));
    std::vector<OperationType> operations;
    operations.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        operations.push_back(co_spawn(executor, task_factory(i), deferred));
    }

    auto group = make_parallel_group(std::move(operations));

    // std::vector<size_t> order;
    // std::vector<std::exception_ptr> exceptions;
    auto [order, exceptions] = co_await group.async_wait(wait_for_one_error(), use_awaitable);
    rethrow_first_exception_if_any(exceptions, order);
}

}  // namespace silkworm::concurrency
