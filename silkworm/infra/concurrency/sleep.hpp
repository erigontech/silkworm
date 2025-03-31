// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>

#include <silkworm/infra/concurrency/task.hpp>

namespace silkworm {

Task<void> sleep(std::chrono::milliseconds duration);

}  // namespace silkworm
