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

#include <boost/asio/executor_work_guard.hpp>

#include "main_chain.hpp"

namespace silkworm::stagedsync {

using namespace boost::asio;

static void ensure(bool condition, const std::string& message) {
    if (!condition) {
        throw std::logic_error("ExtendingFork condition violation: " + message);
    }
}

ExtendingFork::ExtendingFork(BlockId forking_point, MainChain& main_chain, io_context& ctx)
    : forking_point_{forking_point},
      main_chain_{main_chain},
      io_context_{ctx},
      current_head_{forking_point} {}

ExtendingFork::~ExtendingFork() {
    close();
}

BlockId ExtendingFork::current_head() const {
    return current_head_;
}

void ExtendingFork::execution_loop() {
    if (!executor_) return;
    executor_work_guard<decltype(executor_->get_executor())> work{executor_->get_executor()};
    executor_->run();
    if (fork_) fork_->close();  // close the fork here, in the same thread where was created to comply to mdbx limitations
}

void ExtendingFork::start_with(BlockId new_head, std::list<std::shared_ptr<Block>>&& blocks) {
    propagate_exception_if_any();

    executor_ = std::make_unique<io_context>();
    thread_ = std::thread{[this]() { execution_loop(); }};

    current_head_ = new_head;  // setting this here is important for find_fork_by_head() due to the fact that block
                               // insertion and head computation is delayed but find_fork_by_head() is called immediately

    post(*executor_, [this, new_head, blocks_ = std::move(blocks)]() {  // note: this requires a "stable" this pointer
        try {
            if (exception_) return;
            fork_ = std::make_unique<Fork>(forking_point_,
                                           db::ROTxnManaged(main_chain_.tx().db()),
                                           main_chain_.node_settings());  // create the real fork
            fork_->extend_with(blocks_);                                  // extend it with the blocks
            ensure(fork_->current_head() == new_head, "fork head mismatch");
        } catch (...) {
            save_exception(std::current_exception());
        }
    });
}

void ExtendingFork::close() {
    propagate_exception_if_any();
    if (executor_) executor_->stop();
    if (thread_.joinable()) thread_.join();
}

void ExtendingFork::extend_with(Hash head_hash, const Block& head) {
    propagate_exception_if_any();

    current_head_ = {head.header.number, head_hash};  // setting this here is important, same as above

    post(*executor_, [this, block]() {
        try {
            if (exception_) return;
            fork_->extend_with(head);
        } catch (...) {
            save_exception(std::current_exception());
        }
    });
}

concurrency::AwaitableFuture<VerificationResult> ExtendingFork::verify_chain() {
    propagate_exception_if_any();

    concurrency::AwaitablePromise<VerificationResult> promise{io_context_.get_executor()};  // note: promise uses an external io_context
    auto awaitable_future = promise.get_future();

    post(*executor_, [this, promise_ = std::move(promise)]() mutable {
        try {
            if (exception_) return;
            auto result = fork_->verify_chain();
            current_head_ = fork_->current_head();
            promise_.set_value(result);
        } catch (...) {
            save_exception(std::current_exception());
        }
    });

    return awaitable_future;
}

concurrency::AwaitableFuture<bool> ExtendingFork::fork_choice(Hash head_block_hash, std::optional<Hash> finalized_block_hash) {
    propagate_exception_if_any();

    concurrency::AwaitablePromise<bool> promise{io_context_.get_executor()};  // note: promise uses an external io_context
    auto awaitable_future = promise.get_future();

    post(*executor_, [this, promise_ = std::move(promise), head_block_hash, finalized_block_hash]() mutable {
        try {
            if (exception_) return;
            auto updated = fork_->fork_choice(head_block_hash, finalized_block_hash);
            current_head_ = fork_->current_head();
            promise_.set_value(updated);
        } catch (...) {
            save_exception(std::current_exception());
        }
    });

    return awaitable_future;
}

ForkContainer::iterator find_fork_by_head(ForkContainer& forks, const Hash& requested_head_hash) {
    return std::find_if(forks.begin(), forks.end(), [&](const auto& fork) {
        return fork->current_head().hash == requested_head_hash;
    });
}

ForkContainer::iterator find_fork_to_extend(ForkContainer& forks, const BlockHeader& header) {
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
