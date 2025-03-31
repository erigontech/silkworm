// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

/// Use just \silkworm as namespace here to make these definitions available everywhere
/// So that we can write Task<void> foo(); instead of concurrency::Task<void> foo();
namespace silkworm {

//! Asynchronous task returned by any coroutine, i.e. asynchronous operation
template <typename T>
using Task = boost::asio::awaitable<T>;

}  // namespace silkworm
