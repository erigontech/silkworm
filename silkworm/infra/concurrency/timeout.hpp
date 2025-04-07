// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>
#include <stdexcept>

#include <silkworm/infra/concurrency/task.hpp>

namespace silkworm::concurrency {

Task<void> timeout(
    std::chrono::milliseconds duration,
    const char* source_file_path = nullptr,
    int source_file_line = 0);

class TimeoutExpiredError : public std::runtime_error {
  public:
    TimeoutExpiredError() : std::runtime_error("Timeout has expired") {}
};

}  // namespace silkworm::concurrency

#define SILK_CONCURRENCY_TIMEOUT(duration) ::silkworm::concurrency::timeout(duration, __FILE__, __LINE__)
