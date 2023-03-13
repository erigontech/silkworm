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

#include <functional>

#include <silkworm/node/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

namespace silkworm::concurrency {

/**
 * async_thread bridges an async caller code with sync code that requires blocking.
 * It allows awaiting for a blocking `run` function.
 * If `run` throws an exception, it is propagated to the caller.
 * If awaitable is cancelled, the given `stop` function gets called,
 * and is expected that `run` exits after that.
 *
 * @param run thread procedure
 * @param stop a callback to signal the thread procedure to exit
 * @return an awaitable that is pending until the thread finishes
 */
boost::asio::awaitable<void> async_thread(std::function<void()> run, std::function<void()> stop);

}  // namespace silkworm::concurrency
