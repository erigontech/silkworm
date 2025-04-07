// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <boost/asio/any_io_executor.hpp>

namespace silkworm::concurrency {

struct ExecutorPool {
    virtual ~ExecutorPool() = default;
    virtual boost::asio::any_io_executor any_executor() = 0;
};

}  // namespace silkworm::concurrency
