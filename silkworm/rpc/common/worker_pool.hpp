// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <thread>

#include <boost/asio/thread_pool.hpp>

namespace silkworm::rpc {

//! Default number of threads in worker pool (i.e. dedicated to heavier tasks)
inline const uint32_t kDefaultNumWorkers{std::thread::hardware_concurrency() / 2};

//! Pool of worker threads dedicated to heavier tasks
using WorkerPool = boost::asio::thread_pool;

}  // namespace silkworm::rpc
