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

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "fork.hpp"

namespace silkworm::stagedsync {

using boost::asio::awaitable;
using boost::asio::io_context;

class SuspendableFork {
  public:
    explicit SuspendableFork(BlockId forking_point, NodeSettings&, MainChain&);
    SuspendableFork(const SuspendableFork&);
    SuspendableFork(SuspendableFork&& orig) noexcept;

    // contraction
    auto reduce_down_to(BlockId new_head) -> awaitable<void>;

    // verification
    auto verify_chain() -> awaitable<VerificationResult>;
    auto notify_fork_choice_update(Hash head_block_hash,
                                   std::optional<Hash> finalized_block_hash = std::nullopt) -> awaitable<bool>;

  protected:
    Fork fork_;
    io_context& io_context_;
};

}  // namespace silkworm::stagedsync
