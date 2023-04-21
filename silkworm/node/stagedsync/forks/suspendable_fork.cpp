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

static void ensure(bool condition, const std::string& message) {
    if (!condition) {
        throw std::logic_error("ExtendingFork condition violation: " + message);
    }
}

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

auto ExtendingFork::start_with(BlockId new_head, std::list<std::shared_ptr<Block>>&& blocks) -> asio::awaitable<void> {
    current_head_ = new_head;  // setting this here is important for find_fork_by_head() due to the fact that block
                               // insertion and head computation is delayed but find_fork_by_head() is called immediately
    return co_spawn(
        io_context_,
        [](ExtendingFork& me, BlockId new_head, std::list<std::shared_ptr<Block>>&& blocks) -> awaitable<void> {
            me.fork_.open();
            me.fork_.extend_with(blocks);
            ensure(me.fork_.current_head() == new_head, "fork head mismatch");
        }(*this, new_head, std::move(blocks)),
        use_awaitable);
}

auto ExtendingFork::extend_with(Hash head_hash, const Block& block) -> asio::awaitable<void> {
    current_head_ = {block.header.number, head_hash};  // setting this here is important, same as above
    return co_spawn(
        io_context_,
        [](ExtendingFork& me, const Block& block) -> awaitable<void> {
            me.fork_.extend_with(block);
        }(*this, block),
        use_awaitable);
}

auto ExtendingFork::verify_chain() -> concurrency::AwaitableFuture<VerificationResult> {

    concurrency::AwaitablePromise<VerificationResult> promise{io_context_};
    auto awaitable_future = promise.get_future();

    co_spawn(
        io_context_,
        [](ExtendingFork& me, concurrency::AwaitablePromise<VerificationResult>&& promise) -> awaitable<void> {  // avoid using campture in lambda
            auto result = me.fork_.verify_chain();
            me.current_head_ = me.fork_.current_head();
            promise.set_value(result);
        }(*this, std::move(promise)),
        detached);

    return awaitable_future;
}

bool ExtendingFork::notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash) {
    auto result = fork_.notify_fork_choice_update(head_block_hash, finalized_block_hash);
    current_head_ = fork_.current_head();
    return result;
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
