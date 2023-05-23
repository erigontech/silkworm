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

#include "extending_fork.hpp"

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

ExtendingFork::ExtendingFork(BlockId forking_point, MainChain& main_chain, asio::io_context& ctx)
    : forking_point_{forking_point},
      main_chain_{main_chain},
      io_context_{ctx},
      current_head_{forking_point} {}

ExtendingFork::ExtendingFork(ExtendingFork&& orig) noexcept
    : forking_point_{orig.forking_point_},
      main_chain_{orig.main_chain_},
      io_context_{orig.io_context_},
      fork_{std::move(orig.fork_)},
      executor_{std::move(orig.executor_)},
      thread_{std::move(orig.thread_)},
      current_head_{orig.current_head_} {}

ExtendingFork::~ExtendingFork() {
    close();
}

BlockId ExtendingFork::current_head() const {
    return current_head_;
}

void ExtendingFork::execution_loop() {
    if (!executor_) return;
    asio::executor_work_guard<decltype(executor_->get_executor())> work{executor_->get_executor()};
    executor_->run();
}

void ExtendingFork::start_with(BlockId new_head, std::list<std::shared_ptr<Block>>&& blocks) {
    propagate_exception_if_any();

    executor_ = std::make_unique<asio::io_context>();
    thread_ = std::thread{[this]() { execution_loop(); }};

    current_head_ = new_head;  // setting this here is important for find_fork_by_head() due to the fact that block
                               // insertion and head computation is delayed but find_fork_by_head() is called immediately
    auto lambda = [](ExtendingFork& me, BlockId new_head_, std::list<std::shared_ptr<Block>>&& blocks_) -> awaitable<void> {
        me.fork_ = std::make_unique<Fork>(me.forking_point_,
                                          db::ROTxn(me.main_chain_.tx().db()),
                                          me.main_chain_.node_settings());  // create the real fork
        me.fork_->extend_with(blocks_);                                     // extend it with the blocks
        ensure(me.fork_->current_head() == new_head_, "fork head mismatch");
        co_return;
    };

    co_spawn(*executor_, lambda(*this, new_head, std::move(blocks)), [this](std::exception_ptr e) { save_exception(e); });
}

void ExtendingFork::close() {
    propagate_exception_if_any();
    if (fork_) fork_->close();
    if (executor_) executor_->stop();
    if (thread_.joinable()) thread_.join();
}

void ExtendingFork::extend_with(Hash head_hash, const Block& block) {
    propagate_exception_if_any();

    current_head_ = {block.header.number, head_hash};  // setting this here is important, same as above

    auto lambda = [](ExtendingFork& me, const Block& block_) -> awaitable<void> {
        me.fork_->extend_with(block_);
        co_return;
    };

    co_spawn(*executor_, lambda(*this, block), [this](std::exception_ptr e) { save_exception(e); });
}

auto ExtendingFork::verify_chain() -> concurrency::AwaitableFuture<VerificationResult> {
    propagate_exception_if_any();

    concurrency::AwaitablePromise<VerificationResult> promise{io_context_};  // note: promise uses an external io_context
    auto awaitable_future = promise.get_future();

    auto lambda = [](ExtendingFork& me, concurrency::AwaitablePromise<VerificationResult>&& promise_) -> awaitable<void> {
        auto result = me.fork_->verify_chain();
        me.current_head_ = me.fork_->current_head();
        promise_.set_value(result);
        co_return;
    };

    co_spawn(*executor_, lambda(*this, std::move(promise)), [this](std::exception_ptr e) { save_exception(e); });

    return awaitable_future;
}

auto ExtendingFork::notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash)
    -> concurrency::AwaitableFuture<bool> {
    propagate_exception_if_any();

    concurrency::AwaitablePromise<bool> promise{io_context_};  // note: promise uses an external io_context
    auto awaitable_future = promise.get_future();

    auto lambda = [](ExtendingFork& me, concurrency::AwaitablePromise<bool>&& promise_,
                     Hash head, std::optional<Hash> finalized) -> awaitable<void> {
        auto updated = me.fork_->notify_fork_choice_update(head, finalized);
        me.current_head_ = me.fork_->current_head();
        promise_.set_value(updated);
        co_return;
    };

    co_spawn(*executor_, lambda(*this, std::move(promise), head_block_hash, finalized_block_hash),
             [this](std::exception_ptr e) { save_exception(e); });

    return awaitable_future;
}

std::vector<ExtendingFork>::iterator find_fork_by_head(std::vector<ExtendingFork>& forks, const Hash& requested_head_hash) {
    return std::find_if(forks.begin(), forks.end(), [&](const auto& fork) {
        return fork.current_head().hash == requested_head_hash;
    });
}

std::vector<ExtendingFork>::iterator find_fork_to_extend(std::vector<ExtendingFork>& forks, const BlockHeader& header) {
    return find_fork_by_head(forks, header.parent_hash);
}

void ExtendingFork::save_exception(std::exception_ptr e) {
    exception_ = e;  // save exception to rethrow it later
}

void ExtendingFork::propagate_exception_if_any() {
    if (exception_) {
        std::rethrow_exception(exception_);
    }
}

}  // namespace silkworm::stagedsync
