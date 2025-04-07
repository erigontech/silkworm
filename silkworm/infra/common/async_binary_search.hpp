// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>

#include <silkworm/infra/concurrency/task.hpp>

#include <absl/functional/function_ref.h>

namespace silkworm {

using BinaryPredicate = absl::FunctionRef<Task<bool>(size_t)>;

Task<size_t> async_binary_search(size_t n, BinaryPredicate pred);

}  // namespace silkworm
