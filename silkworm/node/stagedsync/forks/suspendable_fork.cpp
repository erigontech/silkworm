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

#include "suspendable_fork.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace silkworm::stagedsync {

using namespace boost::asio;

// a verify_chain() that spawn fork_.verify_chain() in a io_context
// and return a VerificationResult

auto SuspendableFork::verify_chain() -> awaitable<VerificationResult> {
    return co_spawn(
        io_context_, [](Fork* fork) -> awaitable<VerificationResult> {
            auto result = fork->verify_chain();
            co_return result;
        }(&fork_),
        use_awaitable);
}

auto SuspendableFork::reduce_down_to(BlockId new_head) -> awaitable<void> {
    return co_spawn(
        io_context_,
        [](Fork* fork, BlockId new_head) -> awaitable<void> { fork->reduce_down_to(new_head); }(&fork_, new_head),
        use_awaitable);
}

}  // namespace silkworm::stagedsync
