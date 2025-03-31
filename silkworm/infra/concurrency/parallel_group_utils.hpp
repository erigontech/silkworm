// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <exception>
#include <vector>

#include "task.hpp"

#include <absl/functional/function_ref.h>

namespace silkworm::concurrency {

/**
 * Given 2 exceptions rethrows the one which happened first that was unexpected.
 *
 * "Unexpected" can be anything except boost::system::errc::operation_canceled.
 * If all exceptions are operation_canceled, throws one to propagate cancellation.
 * Does not throw with no exceptions (if all exception_ptr are null).
 */
void rethrow_first_exception_if_any(
    const std::array<std::exception_ptr, 2>& exceptions,
    const std::array<size_t, 2>& order);

/**
 * Given some exceptions rethrows the one which happened first that was unexpected.
 *
 * "Unexpected" can be anything except boost::system::errc::operation_canceled.
 * If all exceptions are operation_canceled, throws one to propagate cancellation.
 * Does not throw with no exceptions (if all exception_ptr are null).
 */
void rethrow_first_exception_if_any(
    const std::vector<std::exception_ptr>& exceptions,
    const std::vector<size_t>& order);

/**
 * Build a ranged `parallel_group` task consisting of `count` subtasks produced by `task_factory`:
 * [task_factory(0), task_factory(1), ... task_factory(count - 1)].
 * If one of the subtasks throws, the rest are cancelled and the exception is rethrown.
 */
Task<void> generate_parallel_group_task(size_t count, absl::FunctionRef<Task<void>(size_t)> task_factory);

}  // namespace silkworm::concurrency
