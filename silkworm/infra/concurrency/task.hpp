/*
   Copyright 2023 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#pragma once

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

/// Use just \silkworm as namespace here to make these definitions available everywhere
/// So that we can write Task<void> foo(); instead of concurrency::Task<void> foo();
namespace silkworm {

//! Asynchronous task returned by any coroutine, i.e. asynchronous operation
template <typename T>
using Task = boost::asio::awaitable<T>;

//! Namespace for the current coroutine types
namespace ThisTask = boost::asio::this_coro;  // NOLINT(misc-unused-alias-decls)

//! Executor for asynchronous tasks returned by any coroutine
using TaskExecutor = boost::asio::io_context::executor_type;

}  // namespace silkworm
