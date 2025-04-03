// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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

ExtendingFork::ExtendingFork(
    BlockId forking_point,
    MainChain& main_chain,
    any_io_executor external_executor)
    : forking_point_{forking_point},
      main_chain_{main_chain},
      external_executor_{std::move(external_executor)},
      current_head_{forking_point} {}

ExtendingFork::~ExtendingFork() {
    close();
}

BlockId ExtendingFork::current_head() const {
    return current_head_;
}

void ExtendingFork::execution_loop() {
    if (!ioc_) return;
    executor_work_guard<decltype(ioc_->get_executor())> work{ioc_->get_executor()};
    ioc_->run();
    if (fork_) fork_->close();  // close the fork here, in the same thread where was created to comply to mdbx limitations
}

void ExtendingFork::start_with(BlockId new_head, std::list<std::shared_ptr<Block>> blocks) {
    propagate_exception_if_any();

    ioc_ = std::make_unique<io_context>();
    thread_ = std::thread{[this]() { execution_loop(); }};

    current_head_ = new_head;  // setting this here is important for find_fork_by_head() due to the fact that block
                               // insertion and head computation is delayed but find_fork_by_head() is called immediately

    post(*ioc_, [this, new_head, blocks = std::move(blocks)]() {  // note: this requires a "stable" this pointer
        try {
            if (exception_) return;
            // create the real fork
            fork_ = std::make_unique<Fork>(
                forking_point_,
                datastore::kvdb::ROTxnManaged(main_chain_.tx().db()),
                main_chain_.data_model_factory(),
                main_chain_.log_timer_factory(),
                main_chain_.stages_factory(),
                main_chain_.node_settings().data_directory->forks().path());
            fork_->extend_with(blocks);
            ensure(fork_->current_head() == new_head, "fork head mismatch");
        } catch (...) {
            save_exception(std::current_exception());
        }
    });
}

void ExtendingFork::close() {
    propagate_exception_if_any();
    if (ioc_) ioc_->stop();
    if (thread_.joinable()) thread_.join();
}

void ExtendingFork::extend_with(Hash head_hash, const Block& head) {
    propagate_exception_if_any();

    current_head_ = {head.header.number, head_hash};  // setting this here is important, same as above

    post(*ioc_, [this, head]() {
        try {
            if (exception_) return;
            fork_->extend_with(head);
        } catch (...) {
            save_exception(std::current_exception());
        }
    });
}

ExtendingFork::VerificationResultFuture ExtendingFork::verify_chain() {
    using execution::api::VerificationResult;

    propagate_exception_if_any();

    concurrency::AwaitablePromise<VerificationResult> promise{external_executor_};  // note: promise uses an external io_context
    auto awaitable_future = promise.get_future();

    post(*ioc_, [this, promise = std::move(promise)]() mutable {
        try {
            if (exception_) return;
            auto result = fork_->verify_chain();
            current_head_ = fork_->current_head();
            promise.set_value(result);
        } catch (...) {
            save_exception(std::current_exception());
        }
    });

    return awaitable_future;
}

concurrency::AwaitableFuture<bool> ExtendingFork::fork_choice(Hash head_block_hash,
                                                              std::optional<Hash> finalized_block_hash,
                                                              std::optional<Hash> safe_block_hash) {
    propagate_exception_if_any();

    concurrency::AwaitablePromise<bool> promise{external_executor_};  // note: promise uses an external io_context
    auto awaitable_future = promise.get_future();

    post(*ioc_, [this, promise = std::move(promise), head_block_hash, finalized_block_hash, safe_block_hash]() mutable {
        try {
            if (exception_) return;
            auto updated = fork_->fork_choice(head_block_hash, finalized_block_hash, safe_block_hash);
            current_head_ = fork_->current_head();
            promise.set_value(updated);
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
