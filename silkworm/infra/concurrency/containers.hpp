// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

/*
 * Decisions about concurrent containers
 */

#include <silkworm/infra/concurrency/thread_safe_queue.hpp>

namespace silkworm {

template <typename T>
using ConcurrentQueue =
    ThreadSafeQueue<T>;  // todo: use a better alternative from a known library (Intel oneTBB concurrent_queue<T>?)

}  // namespace silkworm
