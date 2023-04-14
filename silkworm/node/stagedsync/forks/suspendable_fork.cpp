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

#include "main_chain.hpp"

namespace silkworm::stagedsync {

using namespace boost::asio;

ExtendingFork::ExtendingFork(BlockId forking_point, NodeSettings& ns, MainChain& main_chain)
    : memory_db_{TemporaryDirectory::get_unique_temporary_path(ns.data_directory->path())},
      fork_{forking_point, ns, main_chain, memory_db_},
      io_context_{},
      current_head_{fork_.current_head()} {}

ExtendingFork::ExtendingFork(ExtendingFork&& orig) noexcept
    : memory_db_{std::move(orig.memory_db_)},
      fork_{std::move(orig.fork_)},
      io_context_{std::move(orig.io_context_)},
      current_head_{orig.current_head_} {}

BlockId ExtendingFork::current_head() const {
    return current_head_;
}

auto ExtendingFork::verify_chain() -> awaitable<VerificationResult> {
    return co_spawn(
        io_context_,
        [](ExtendingFork& me) -> awaitable<VerificationResult> {  // avoid using campture in lambda
            auto result = me.fork_.verify_chain();
            me.current_head_ = me.fork_.current_head();
            co_return result;
        }(*this),
        use_awaitable);
}

auto ExtendingFork::extend_with(std::list<std::shared_ptr<Block>>&& blocks) -> asio::awaitable<void> {
    return co_spawn(
        io_context_,
        [](ExtendingFork& me, std::list<std::shared_ptr<Block>>&& blocks) -> awaitable<void> {
            me.fork_.extend_with(blocks);
            me.current_head_ = me.fork_.current_head();
        }(*this, std::move(blocks)),
        use_awaitable);
}

auto ExtendingFork::reduce_down_to(BlockId new_head) -> awaitable<void> {
    return co_spawn(
        io_context_,
        [](ExtendingFork& me, BlockId new_head) -> awaitable<void> {
            me.fork_.reduce_down_to(new_head);
            me.current_head_ = me.fork_.current_head();
        }(*this, new_head),
        use_awaitable);
}

std::vector<ExtendingFork>::iterator find_fork_by_head(std::vector<ExtendingFork>& forks, const Hash& requested_head_hash) {
    return std::find_if(forks.begin(), forks.end(), [&](const auto& fork) {
        return fork.current_head().hash == requested_head_hash;
    });
}

std::vector<ExtendingFork>::iterator find_fork_to_extend(std::vector<ExtendingFork>& forks, const BlockHeader& header) {
    return find_fork_by_head(forks, header.parent_hash);
}

}  // namespace silkworm::stagedsync
