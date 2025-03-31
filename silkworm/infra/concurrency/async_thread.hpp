// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <optional>

#include <silkworm/infra/concurrency/task.hpp>

namespace silkworm::concurrency {

/**
 * async_thread bridges an async caller code with sync code that requires blocking.
 * It allows awaiting for a blocking `run` function.
 * If `run` throws an exception, it is propagated to the caller.
 * If a returned task is cancelled, the given `stop` function gets called,
 * and is expected that `run` exits after that.
 *
 * @param run thread procedure
 * @param stop a callback to signal the thread procedure to exit
 * @param name the name appearing in log traces for the created thread
 * @param stack_size optional custom stack size for the created thread
 * @return an task that is pending until the thread finishes
 */
Task<void> async_thread(
    std::function<void()> run,
    std::function<void()> stop,
    const char* name,
    std::optional<size_t> stack_size = {});

}  // namespace silkworm::concurrency
