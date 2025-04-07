// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <thread>

namespace silkworm::concurrency {

//! Default number of threads to use for I/O tasks
inline const uint32_t kDefaultNumContexts{std::thread::hardware_concurrency() / 2};

//! The configuration settings for \refitem ContextPool
struct ContextPoolSettings {
    uint32_t num_contexts{kDefaultNumContexts};  // The number of execution contexts to activate
};

}  // namespace silkworm::concurrency
